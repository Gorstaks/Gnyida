#:package Microsoft.CodeAnalysis.CSharp@4.*
// Parses every .cs file under a path with Roslyn and reports problems. Report-only unless --fail-on is given.
//
// Rules
//   SYNTAX          C# syntax errors reported by the parser
//   SLEEP           Thread.Sleep (constraint: no Thread.Sleep without cancellation)
//   EMPTY-CATCH     catch block with no statements (constraint: no silent exception swallowing)
//   SHELL-INTERP    interpolated string used as Process.Start argument or .Arguments value
//   STRING-JSON     string literal that looks like hand-built JSON (constraint: use System.Text.Json)
//   STATIC-MUTABLE  static field that is neither readonly nor const (constraint: no static mutable state)
//   NUMBER          numeric literals other than 0/1/2 (only with --numbers; for magic-number review)
//
// Findings are heuristics for review, not verdicts.
//
// Usage
//   dotnet run tools/validation/SourceScan.cs
//   dotnet run tools/validation/SourceScan.cs -- --path src/Gnyida.Core --numbers
//   dotnet run tools/validation/SourceScan.cs -- --fail-on SYNTAX,SLEEP

using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

string path = "src";
bool numbers = false;
var failOn = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--path": path = args[++i]; break;
        case "--numbers": numbers = true; break;
        case "--fail-on": foreach (var r in args[++i].Split(',', StringSplitOptions.RemoveEmptyEntries)) failOn.Add(r.Trim()); break;
        default: Console.Error.WriteLine($"Unknown argument: {args[i]}"); return 2;
    }
}

string root = Path.GetFullPath(path);
var jsonLike = new Regex(@"\{\s*\\?""[A-Za-z_]\w*\\?""\s*:", RegexOptions.Compiled);
var findings = new List<(string Rule, string File, int Line, string Msg)>();

var files = Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories)
    .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
              && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
    .ToList();

foreach (var file in files)
{
    string rel = Path.GetRelativePath(root, file);
    var tree = CSharpSyntaxTree.ParseText(File.ReadAllText(file), path: file);

    void Add(string rule, TextSpanHolder at, string msg) =>
        findings.Add((rule, rel, tree.GetLineSpan(at.Span).StartLinePosition.Line + 1, msg));

    foreach (var d in tree.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error))
        Add("SYNTAX", new(d.Location.SourceSpan), d.GetMessage());

    foreach (var node in tree.GetRoot().DescendantNodes())
    {
        switch (node)
        {
            case InvocationExpressionSyntax inv:
                string callee = inv.Expression.ToString();
                if (callee is "Thread.Sleep" or "System.Threading.Thread.Sleep")
                    Add("SLEEP", new(inv.Span), inv.ToString());
                if (Regex.IsMatch(callee, @"(^|\.)Process\.Start$") &&
                    inv.ArgumentList.Arguments.Count >= 2 &&
                    inv.ArgumentList.Arguments.Any(a => a.Expression is InterpolatedStringExpressionSyntax))
                    Add("SHELL-INTERP", new(inv.Span), "Process.Start with interpolated argument");
                break;

            case CatchClauseSyntax c when c.Block.Statements.Count == 0:
                string method = c.Ancestors().OfType<BaseMethodDeclarationSyntax>().FirstOrDefault() is { } m
                    ? (m is MethodDeclarationSyntax md ? md.Identifier.Text : m.Kind().ToString())
                    : (c.Ancestors().OfType<LocalFunctionStatementSyntax>().FirstOrDefault()?.Identifier.Text ?? "?");
                string ctype = c.Declaration?.Type.ToString() ?? "(all)";
                string tryFirst = c.Parent is TryStatementSyntax ts && ts.Block.Statements.Count > 0
                    ? Trim(ts.Block.Statements[0].ToString()) : "";
                bool commented = c.Block.DescendantTrivia().Any(t => t.IsKind(SyntaxKind.SingleLineCommentTrivia) || t.IsKind(SyntaxKind.MultiLineCommentTrivia))
                    || c.Block.OpenBraceToken.TrailingTrivia.Any(t => t.IsKind(SyntaxKind.SingleLineCommentTrivia))
                    || c.CatchKeyword.TrailingTrivia.Any(t => t.IsKind(SyntaxKind.SingleLineCommentTrivia));
                Add("EMPTY-CATCH", new(c.Span), $"{(commented ? "commented" : "bare")} | catch {ctype} | in {method} | try: {tryFirst}");
                break;

            case AssignmentExpressionSyntax a when
                a.IsKind(SyntaxKind.SimpleAssignmentExpression) &&
                Regex.IsMatch(a.Left.ToString(), @"(^|\.)Arguments$") &&
                a.Right is InterpolatedStringExpressionSyntax:
                Add("SHELL-INTERP", new(a.Span), "Arguments assigned from interpolated string");
                break;

            case LiteralExpressionSyntax lit when lit.IsKind(SyntaxKind.StringLiteralExpression):
                if (jsonLike.IsMatch(lit.Token.ValueText))
                    Add("STRING-JSON", new(lit.Span), Trim(lit.ToString()));
                break;

            case InterpolatedStringExpressionSyntax interp:
                if (jsonLike.IsMatch(interp.ToString()))
                    Add("STRING-JSON", new(interp.Span), Trim(interp.ToString()));
                break;

            case FieldDeclarationSyntax fd:
                bool isStatic = fd.Modifiers.Any(SyntaxKind.StaticKeyword);
                bool immutable = fd.Modifiers.Any(SyntaxKind.ReadOnlyKeyword) || fd.Modifiers.Any(SyntaxKind.ConstKeyword);
                if (isStatic && !immutable)
                    Add("STATIC-MUTABLE", new(fd.Span), Trim(fd.Declaration.ToString()));
                break;

            case LiteralExpressionSyntax num when numbers && num.IsKind(SyntaxKind.NumericLiteralExpression):
                if (num.Token.ValueText is not ("0" or "1" or "2" or "0.0" or "1.0"))
                    Add("NUMBER", new(num.Span), num.ToString());
                break;
        }
    }
}

static string Trim(string s)
{
    s = s.ReplaceLineEndings(" ");
    return s.Length <= 80 ? s : s[..80] + "...";
}

Console.WriteLine($"Scanned {files.Count} files under {path}");
foreach (var g in findings.GroupBy(f => f.Rule).OrderBy(g => g.Key))
    Console.WriteLine($"  {g.Key,-15}{g.Count()}");
Console.WriteLine();
foreach (var f in findings.OrderBy(f => f.Rule).ThenBy(f => f.File).ThenBy(f => f.Line))
    Console.WriteLine($"{f.File}:{f.Line}  [{f.Rule}]  {f.Msg}");

int bad = findings.Count(f => failOn.Contains(f.Rule));
if (bad > 0) { Console.WriteLine($"::error::SourceScan: {bad} finding(s) in fail-on rules"); return 1; }
return 0;

readonly record struct TextSpanHolder(Microsoft.CodeAnalysis.Text.TextSpan Span);
