using System;
using System.Management.Automation;
using System.Runtime.InteropServices;

namespace StartProcessLongFilePathCmdlet
{
    [Cmdlet(VerbsLifecycle.Start, "ProcessLongFilePath")]
    public class StartProcessLongFilePathCommand : Cmdlet
    {
        [Parameter(Mandatory = true, Position = 0)]
        public string Path { get; set; } = string.Empty;

        [Parameter(Position = 1)]
        public string Arguments { get; set; } = string.Empty;

        protected override void ProcessRecord()
        {
            string exe = @"\\?\" + System.IO.Path.GetFullPath(Path);
            string cmdLine = $"\"{exe}\" {Arguments}".Trim();

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            PROCESS_INFORMATION pi;

            bool success = CreateProcessW(
                lpApplicationName: exe,
                lpCommandLine: cmdLine,
                lpProcessAttributes: IntPtr.Zero,
                lpThreadAttributes: IntPtr.Zero,
                bInheritHandles: false,
                dwCreationFlags: 0,
                lpEnvironment: IntPtr.Zero,
                lpCurrentDirectory: null!, // use null! to suppress nullable warning
                lpStartupInfo: ref si,
                lpProcessInformation: out pi
            );

            if (!success)
            {
                int error = Marshal.GetLastWin32Error();
                ThrowTerminatingError(new ErrorRecord(
                    new System.ComponentModel.Win32Exception(error),
                    "CreateProcessWFailed",
                    ErrorCategory.ResourceUnavailable,
                    exe
                ));
            }

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        [StructLayout(LayoutKind.Sequential)]
        struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX, dwY, dwXSize, dwYSize;
            public int dwXCountChars, dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION
        {
            public IntPtr hProcess, hThread;
            public int dwProcessId, dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessW(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);
    }
}