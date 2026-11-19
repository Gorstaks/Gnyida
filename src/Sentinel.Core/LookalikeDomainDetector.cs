using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
namespace Sentinel.Core
{
    /// <summary>
    /// "Real site" check: flags a queried domain that imitates a well-known brand through
    /// look-alike characters (Cyrillic/Greek letters, 0/1 for o/l, rn for m), a one-character typo,
    /// or the brand's real domain placed in front of a different registrable domain
    /// (paypal.com.example.net). Pure function; the caller reports it as Tier2 / LogOnly.
    /// </summary>
    internal static class LookalikeDomainDetector
    {
        // Brand label -> real registrable domains. A label that matches a brand on another TLD
        // (for example brand.net) is not flagged: only imitation is.
        private static readonly Dictionary<string, string[]> Brands = new(StringComparer.Ordinal)
        {
            ["paypal"] = new[] { "paypal.com", "paypal.me" },
            ["microsoft"] = new[] { "microsoft.com", "microsoftonline.com" },
            ["google"] = new[] { "google.com", "googleapis.com", "google.co.uk" },
            ["amazon"] = new[] { "amazon.com", "amazonaws.com", "amazon.co.uk", "amazon.de" },
            ["apple"] = new[] { "apple.com", "icloud.com" },
            ["facebook"] = new[] { "facebook.com", "fb.com" },
            ["instagram"] = new[] { "instagram.com" },
            ["whatsapp"] = new[] { "whatsapp.com", "whatsapp.net" },
            ["netflix"] = new[] { "netflix.com", "nflxvideo.net" },
            ["linkedin"] = new[] { "linkedin.com" },
            ["twitter"] = new[] { "twitter.com", "x.com" },
            ["github"] = new[] { "github.com", "githubusercontent.com", "github.io" },
            ["dropbox"] = new[] { "dropbox.com" },
            ["discord"] = new[] { "discord.com", "discordapp.com", "discord.gg" },
            ["steampowered"] = new[] { "steampowered.com" },
            ["binance"] = new[] { "binance.com" },
            ["coinbase"] = new[] { "coinbase.com" },
            ["metamask"] = new[] { "metamask.io" },
            ["wellsfargo"] = new[] { "wellsfargo.com" },
            ["bankofamerica"] = new[] { "bankofamerica.com" },
            ["avast"] = new[] { "avast.com", "avcdn.net" },
        };
        private static readonly HashSet<string> TwoLevelSuffixes = new(StringComparer.Ordinal)
        {
            "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.nz", "co.jp", "co.in", "com.br", "com.tr", "co.za", "com.mx",
        };
        // Characters that render like a Latin letter. Scripts are mixed on purpose to imitate a brand.
        private static readonly Dictionary<char, char> Confusables = new()
        {
            ['\u0430'] = 'a', ['\u0435'] = 'e', ['\u043E'] = 'o', ['\u0440'] = 'p', ['\u0441'] = 'c', ['\u0445'] = 'x',
            ['\u0443'] = 'y', ['\u0456'] = 'i', ['\u0458'] = 'j', ['\u04CF'] = 'l', ['\u0455'] = 's',
            ['\u03BF'] = 'o', ['\u03B1'] = 'a', ['\u03C1'] = 'p', ['\u03B9'] = 'i', ['\u03BD'] = 'v',
            ['0'] = 'o', ['1'] = 'l',
        };
        internal readonly struct Verdict
        {
            public Verdict(string brand, string reason) { Brand = brand; Reason = reason; }
            public string Brand { get; }
            public string Reason { get; }
        }
        internal static Verdict? Evaluate(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain)) return null;
            // Same mapping the client applies (fullwidth letters, ideographic dots, invisible characters), but the labels stay
            // Unicode: the confusable check below needs the original characters, not their punycode.
            var host = HostNormalizer.NormalizeText(domain).Trim().TrimEnd('.');
            var labels = host.Split('.');
            if (labels.Length < 2) return null;
            var baseDomain = BaseDomain(labels);
            // The brand's own registrable domain (or a subdomain of it) is never an imitation.
            foreach (var real in AllRealDomains()) if (baseDomain == real) return null;
            var baseLabel = baseDomain.Split('.')[0];
            var unicodeLabel = ToUnicode(baseLabel);
            var skeleton = Skeleton(unicodeLabel);
            foreach (var brand in Brands.Keys)
            {
                if (skeleton == brand && unicodeLabel != brand)
                    return new Verdict(brand, "look-alike characters imitate the brand name");
                if (brand.Length >= 7 && skeleton != brand && IsOneEditAway(skeleton, brand))
                    return new Verdict(brand, "one-character typo of the brand name");
            }
            // Brand's real domain used as a prefix of someone else's domain.
            for (int i = 0; i + 1 < labels.Length; i++)
            {
                foreach (var kv in Brands)
                {
                    foreach (var real in kv.Value)
                    {
                        var first = real.Split('.')[0];
                        if (labels[i] == first && baseLabel != first && i < labels.Length - 2 && baseDomain != real)
                        {
                            // "paypal.com.evil.net": brand label followed by its TLD label.
                            var next = labels[i + 1];
                            if (real.Substring(first.Length + 1).StartsWith(next, StringComparison.Ordinal))
                                return new Verdict(kv.Key, "brand's domain is placed in front of a different registrable domain");
                        }
                    }
                }
            }
            return null;
        }
        private static IEnumerable<string> AllRealDomains()
        {
            foreach (var v in Brands.Values) foreach (var d in v) yield return d;
        }
        private static string BaseDomain(string[] labels)
        {
            int n = labels.Length;
            if (n >= 3 && TwoLevelSuffixes.Contains(labels[n - 2] + "." + labels[n - 1]))
                return labels[n - 3] + "." + labels[n - 2] + "." + labels[n - 1];
            return labels[n - 2] + "." + labels[n - 1];
        }
        private static string ToUnicode(string label)
        {
            if (!label.StartsWith("xn--", StringComparison.Ordinal)) return label;
            try { return new IdnMapping().GetUnicode(label); }
            catch (ArgumentException) { return label; }
        }
        private static string Skeleton(string label)
        {
            var sb = new StringBuilder(label.Length);
            foreach (var ch in label)
                sb.Append(Confusables.TryGetValue(ch, out var m) ? m : ch);
            return sb.ToString().Replace("rn", "m").Replace("vv", "w");
        }
        private static bool IsOneEditAway(string a, string b)
        {
            if (Math.Abs(a.Length - b.Length) > 1) return false;
            int i = 0, j = 0, edits = 0;
            while (i < a.Length && j < b.Length)
            {
                if (a[i] == b[j]) { i++; j++; continue; }
                if (++edits > 1) return false;
                if (a.Length > b.Length) i++;
                else if (a.Length < b.Length) j++;
                else { i++; j++; }
            }
            return edits + (a.Length - i) + (b.Length - j) <= 1;
        }
    }
}