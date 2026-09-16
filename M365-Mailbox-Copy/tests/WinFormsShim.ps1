<#
.SYNOPSIS
    Makes the copy tool's WinForms parameter types resolvable off Windows.

.DESCRIPTION
    Several functions in M365-Mailbox-Copy-Tool.ps1 constrain parameters to
    [System.Windows.Forms.TextBox] / [System.Windows.Forms.ProgressBar]. On
    Windows the real assembly is loaded; anywhere else these minimal stand-ins
    are defined under the same names so the functions can be called unchanged.
    The stand-in TextBox accumulates everything appended to it in .Text, exactly
    like the real control, so a test can read the status log either way.
#>

if ([type]::GetType('System.Windows.Forms.TextBox') -or
    ([appdomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'System.Windows.Forms' })) {
    return
}

try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    return
}
catch {
    # Not Windows: fall through and define the stand-ins.
}

Add-Type -TypeDefinition @'
using System.Text;

namespace System.Windows.Forms
{
    public class TextBox
    {
        private readonly StringBuilder _text = new StringBuilder();

        public string Text
        {
            get { return _text.ToString(); }
            set { _text.Length = 0; _text.Append(value); }
        }

        public void AppendText(string text) { _text.Append(text); }
        public void Clear() { _text.Length = 0; }
        public void Refresh() { }
    }

    public class ProgressBar
    {
        public int Value { get; set; }
        public void Refresh() { }
    }

    public static class Application
    {
        public static void DoEvents() { }
    }
}
'@
