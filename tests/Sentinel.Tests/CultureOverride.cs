using System;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Threading;

// net48 has no ModuleInitializerAttribute; the compiler only needs a type with this name and shape.
namespace System.Runtime.CompilerServices
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    internal sealed class ModuleInitializerAttribute : Attribute { }
}

namespace Sentinel.Tests
{
    /// <summary>
    /// Runs the whole suite under another culture when SENTINEL_TEST_CULTURE is set (for example tr-TR or de-DE).
    /// Sentinel runs as a service whose culture is the machine's system locale, so behavior that only works under
    /// en-US is a defect on most of the world's machines. Unset, this does nothing.
    ///   $env:SENTINEL_TEST_CULTURE = 'tr-TR'; dotnet test
    /// </summary>
    internal static class CultureOverride
    {
#pragma warning disable CA2255 // Deliberate: the culture has to be set before any test in this assembly runs.
        [ModuleInitializer]
        internal static void Apply()
        {
            string? name = Environment.GetEnvironmentVariable("SENTINEL_TEST_CULTURE");
            if (string.IsNullOrWhiteSpace(name)) return;
            CultureInfo culture;
            try { culture = CultureInfo.GetCultureInfo(name!.Trim()); }
            catch (CultureNotFoundException) { return; }
            CultureInfo.DefaultThreadCurrentCulture = culture;
            CultureInfo.DefaultThreadCurrentUICulture = culture;
            Thread.CurrentThread.CurrentCulture = culture;
            Thread.CurrentThread.CurrentUICulture = culture;
        }
#pragma warning restore CA2255
    }
}
