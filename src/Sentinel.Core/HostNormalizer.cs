using System;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Sentinel.Core
{
    /// <summary>
    /// One normal form for host names and for text that contains URLs, so that matching sees what the network client sees.
    ///
    /// Why: the sink and brand lists are ASCII. .NET (and browsers) map several spellings of a host to that ASCII name
    /// before connecting: a trailing dot, the ideographic full stop U+3002 or fullwidth U+FF0E as a label separator,
    /// invisible characters that IDNA drops (soft hyphen, zero-width joiner or space), fullwidth letters, and unreserved
    /// characters written as %XX. A comparison that does not apply the same mapping never sees the match, so
    /// "https://webhook<U+3002>site/" reached webhook.site while the sink check said no.
    ///
    /// Not a security boundary on its own: it makes text and host comparisons agree with the client. Look-alike names that
    /// map to a DIFFERENT host (a Cyrillic letter in a brand name) must still differ, and do.
    /// </summary>
    internal static class HostNormalizer
    {
        private static readonly Regex Percent = new Regex("%(?<h>[0-9A-Fa-f]{2})", RegexOptions.CultureInvariant);

        private static bool IsIgnorable(char c) =>
            c == '\u00AD' || c == '\u034F' || c == '\u061C' || c == '\u115F' || c == '\u1160' ||
            c == '\u17B4' || c == '\u17B5' || (c >= '\u180B' && c <= '\u180E') ||
            (c >= '\u200B' && c <= '\u200F') || (c >= '\u202A' && c <= '\u202E') ||
            (c >= '\u2060' && c <= '\u206F') || c == '\u3164' || (c >= '\uFE00' && c <= '\uFE0F') ||
            c == '\uFEFF' || c == '\uFFA0';

        private static bool IsUnreserved(char c) =>
            (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~';

        /// <summary>
        /// Text prepared for substring matching of URLs and host names. Lower case; ignorable characters removed; the
        /// ideographic and fullwidth full stops become '.'; compatibility forms (fullwidth letters) map to ASCII; and
        /// unreserved characters written as %XX are decoded. Pure ASCII text without '%' takes a fast path.
        /// </summary>
        internal static string NormalizeText(string? text)
        {
            if (string.IsNullOrEmpty(text)) return "";
            bool plain = true;
            foreach (char c in text!)
            {
                if (c > '~' || c == '%') { plain = false; break; }
            }
            if (plain) return text!.ToLowerInvariant();

            var sb = new StringBuilder(text!.Length);
            foreach (char c in text)
            {
                if (IsIgnorable(c)) continue;
                sb.Append(c == '\u3002' || c == '\uFF0E' || c == '\uFF61' ? '.' : c);
            }
            string s = sb.ToString();
            try { s = s.Normalize(NormalizationForm.FormKC); }
            catch (ArgumentException ex) { /* a lone surrogate: leave the text as it is */ BestEffort.Debug(ex, "HostNormalizer.NormalizeText()"); }
            s = Percent.Replace(s, m =>
            {
                char decoded = (char)Convert.ToInt32(m.Groups["h"].Value, 16);
                return IsUnreserved(decoded) ? decoded.ToString() : m.Value;
            });
            return s.ToLowerInvariant();
        }

        /// <summary>
        /// The host a client would connect to, from a bare host name or a URL: normalized text, authority only (no
        /// credentials, port or path), IDNA-mapped to ASCII, no trailing dot. Empty when there is no host.
        /// </summary>
        internal static string Normalize(string? hostOrUrl)
        {
            if (string.IsNullOrWhiteSpace(hostOrUrl)) return "";
            string s = NormalizeText(hostOrUrl).Trim();
            string host = s;
            int scheme = s.IndexOf("://", StringComparison.Ordinal);
            if (scheme > 0)
            {
                if (Uri.TryCreate(s, UriKind.Absolute, out Uri? uri) && !string.IsNullOrEmpty(uri.IdnHost))
                {
                    host = uri.IdnHost;
                }
                else
                {
                    // Not parseable as a URL: take the authority by hand so the check still has something to compare.
                    string rest = s.Substring(scheme + 3);
                    int end = rest.IndexOfAny(new[] { '/', '?', '#' });
                    if (end >= 0) rest = rest.Substring(0, end);
                    int at = rest.LastIndexOf('@');
                    if (at >= 0) rest = rest.Substring(at + 1);
                    int colon = rest.LastIndexOf(':');
                    if (colon >= 0 && rest.IndexOf(']') < colon) rest = rest.Substring(0, colon);
                    host = rest;
                }
            }
            host = host.Trim().TrimEnd('.');
            if (host.Length > 0 && !IsAscii(host))
            {
                try { host = new IdnMapping().GetAscii(host); }
                catch (ArgumentException ex) { /* not a valid name: keep the text, it will not match a list entry */ BestEffort.Debug(ex, "HostNormalizer.Normalize()"); }
            }
            return host.TrimEnd('.').ToLowerInvariant();
        }

        private static bool IsAscii(string s)
        {
            foreach (char c in s) if (c > '~') return false;
            return true;
        }
    }
}
