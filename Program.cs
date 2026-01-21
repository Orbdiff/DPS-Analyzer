using System;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Security.Principal;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

[SupportedOSPlatform("windows")]
class Program
{
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_READ = 0x0010;

    static StreamWriter writer = null!;
    static StreamWriter parsedWriter = null!;
    static StreamWriter queryWriter = null!;
    static StreamWriter suspiciousWriter = null!;

    static HashSet<string> seen = new HashSet<string>();
    static HashSet<string> parsedSeen = new HashSet<string>();
    static HashSet<string> querySeen = new HashSet<string>();

    static Dictionary<string, string> deviceMap =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    static void Main()
    {
        BuildDeviceMap();

        if (!ElevateDebugPrivilege())
        {
            Console.WriteLine("[-] Debug privileges elevation failed");
            return;
        }

        int pid = GetDpsPid();
        if (pid == 0)
        {
            Console.WriteLine("[-] DPS process not located");
            return;
        }

        Console.WriteLine($"[+] DPS PID: {pid}");

        IntPtr hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);

        if (hProcess == IntPtr.Zero)
        {
            Console.WriteLine("[-] Process opening unsuccessful (admin privileges required)");
            return;
        }

        using (writer = new StreamWriter("dps_strings.txt", false, Encoding.UTF8))
        using (parsedWriter = new StreamWriter("dps-parsed-results.txt", false, Encoding.UTF8))
        using (queryWriter = new StreamWriter("dps-query-results.txt", false, Encoding.UTF8))
        {
            ScanMemory(hProcess);
        }

        CloseHandle(hProcess);

        var exeDates = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var queryLines = File.ReadAllLines("dps-query-results.txt");
        foreach (var line in queryLines)
        {
            string exeName = ExtractExeFromQuery(line);
            string date = ExtractDateFromQuery(line);
            if (!string.IsNullOrEmpty(exeName) && !string.IsNullOrEmpty(date))
            {
                if (!exeDates.TryGetValue(exeName, out var dates))
                {
                    dates = new HashSet<string>();
                    exeDates[exeName] = dates;
                }
                dates.Add(date);
            }
        }

        using (suspiciousWriter = new StreamWriter("dps-suspicious-results.txt", false, Encoding.UTF8))
        {
            foreach (var kv in exeDates)
            {
                if (kv.Value.Count > 1)
                {
                    foreach (var date in kv.Value)
                    {
                        suspiciousWriter.WriteLine($"!!{kv.Key}!{date}!");
                    }
                }
            }
        }

        Console.WriteLine("[+] dps_strings.txt");
        Console.WriteLine("[+] dps-parsed-results.txt");
        Console.WriteLine("[+] dps-query-results.txt");
        Console.WriteLine("[+] dps-suspicious-results.txt");

        using (var parsedPathsWriter = new StreamWriter("dps-parsed-paths.txt", false, Encoding.UTF8))
        {
            var suspiciousExes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var suspiciousLines = File.ReadAllLines("dps-suspicious-results.txt");
            foreach (var line in suspiciousLines)
            {
                string exeName = ExtractExeFromSuspicious(line);
                if (!string.IsNullOrEmpty(exeName))
                {
                    suspiciousExes.Add(exeName);
                }
            }

            var parsedLines = File.ReadAllLines("dps-parsed-results.txt");
            foreach (var line in parsedLines)
            {
                int lastSlash = line.LastIndexOfAny(new[] { '\\', '/' });
                if (lastSlash != -1)
                {
                    string exe = line.Substring(lastSlash + 1);
                    if (suspiciousExes.Contains(exe))
                    {
                        string signatureStatus = GetSignatureStatus(line);
                        parsedPathsWriter.WriteLine($"{signatureStatus} | {line}");
                    }
                }
            }
        }

        Console.WriteLine("[+] dps-parsed-paths.txt");

        using (var fullSigcheckWriter = new StreamWriter("dps-full-sigcheck-executables.txt", false, Encoding.UTF8))
        {
            var parsedLines = File.ReadAllLines("dps-parsed-results.txt");
            foreach (var line in parsedLines)
            {
                string signatureStatus = GetSignatureStatus(line);
                fullSigcheckWriter.WriteLine($"{signatureStatus} | {line}");
            }
        }

        Console.WriteLine("[+] dps-full-sigcheck-executables.txt");

        using (var unsignedWriter = new StreamWriter("dps-full-unsigned-executables.txt", false, Encoding.UTF8))
        using (var notfoundWriter = new StreamWriter("dps-full-notfound-executables.txt", false, Encoding.UTF8))
        {
            var sigcheckLines = File.ReadAllLines("dps-full-sigcheck-executables.txt");
            foreach (var line in sigcheckLines)
            {
                if (line.StartsWith("Unsigned |") || line.StartsWith("Fake Sig |") || line.StartsWith("Local Sig |"))
                {
                    unsignedWriter.WriteLine(line);
                }
                else if (line.StartsWith("NotFound |"))
                {
                    notfoundWriter.WriteLine(line);
                }
            }
        }

        Console.WriteLine("[+] dps-full-unsigned-executables.txt");
        Console.WriteLine("[+] dps-full-notfound-executables.txt");

        System.Threading.Thread.Sleep(3000);
        Environment.Exit(0);
    }

    static string GetSignatureStatus(string filePath)
    {
        if (!File.Exists(filePath))
            return "NotFound";

        try
        {
#pragma warning disable SYSLIB0057
            X509Certificate cert = X509Certificate2.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
            X509Certificate2 cert2 = new X509Certificate2(cert);

            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority | X509VerificationFlags.IgnoreNotTimeValid;

            bool isValid = chain.Build(cert2);

            if (isValid && chain.ChainElements.Count > 1)
            {
                return "Signed";
            }
            else if (cert2.Subject == cert2.Issuer)
            {
                return "Local Sig";
            }
            else
            {
                return "Fake Sig";
            }
        }
        catch
        {
            return "Unsigned";
        }
    }

    static string ExtractExeFromQuery(string line)
    {
        int start = line.IndexOf("!!");
        if (start == -1) return string.Empty;

        start += 2;
        int end = line.IndexOf('!', start);
        if (end == -1) return string.Empty;

        string exe = line.Substring(start, end - start);
        if (exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            return exe;

        return string.Empty;
    }

    static string ExtractDateFromQuery(string line)
    {
        int start = line.IndexOf("!!");
        if (start == -1) return string.Empty;

        start += 2;
        int exeEnd = line.IndexOf('!', start);
        if (exeEnd == -1) return string.Empty;

        int dateStart = exeEnd + 1;
        int dateEnd = line.IndexOf('!', dateStart);
        if (dateEnd == -1) return string.Empty;

        return line.Substring(dateStart, dateEnd - dateStart);
    }

    static string ExtractExeFromSuspicious(string line)
    {
        int start = line.IndexOf("!!");
        if (start == -1) return string.Empty;

        start += 2;
        int end = line.IndexOf('!', start);
        if (end == -1) return string.Empty;

        string exe = line.Substring(start, end - start);
        if (exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            return exe;

        return string.Empty;
    }

    static bool ElevateDebugPrivilege()
    {
        IntPtr hToken = IntPtr.Zero;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
            return false;

        LUID luid;
#pragma warning disable CS8625
        if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, out luid))
#pragma warning restore CS8625
        {
            CloseHandle(hToken);
            return false;
        }

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges = new LUID_AND_ATTRIBUTES[1];
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
        {
            CloseHandle(hToken);
            return false;
        }

        CloseHandle(hToken);
        return true;
    }

    static void BuildDeviceMap()
    {
        for (char c = 'A'; c <= 'Z'; c++)
        {
            string drive = c + ":";
            var sb = new StringBuilder(260);

            if (QueryDosDevice(drive, sb, sb.Capacity) != 0)
            {
                string device = sb.ToString();
                if (!deviceMap.ContainsKey(device))
                    deviceMap[device] = drive;
            }
        }
    }

    static string ConvertDevicePathToDosPath(string path)
    {
        foreach (var kv in deviceMap)
        {
            if (path.StartsWith(kv.Key, StringComparison.OrdinalIgnoreCase))
                return kv.Value + path.Substring(kv.Key.Length);
        }
        return path;
    }

    static int GetDpsPid()
    {
        using var searcher =
            new ManagementObjectSearcher(
                "SELECT ProcessId FROM Win32_Service WHERE Name='DPS'");

        foreach (ManagementObject obj in searcher.Get())
            return Convert.ToInt32(obj["ProcessId"]);

        return 0;
    }

    static void ScanMemory(IntPtr hProcess)
    {
        ulong address = 0;
        MEMORY_BASIC_INFORMATION mbi;

        while (VirtualQueryEx(
            hProcess,
            (IntPtr)address,
            out mbi,
            (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0)
        {
            if (mbi.State == MEM_COMMIT && IsReadable(mbi.Protect))
            {
                byte[] buffer = new byte[(int)mbi.RegionSize];

                if (ReadProcessMemory(
                    hProcess,
                    mbi.BaseAddress,
                    buffer,
                    buffer.Length,
                    out _))
                {
                    ExtractAscii(buffer, 5);
                    ExtractUnicodeUtf16(buffer, 5);
                }
            }

            address += (ulong)mbi.RegionSize;
        }
    }

    static void ExtractAscii(byte[] data, int minLen)
    {
        var sb = new StringBuilder();

        foreach (byte b in data)
        {
            if (b >= 32 && b <= 126)
                sb.Append((char)b);
            else
                Flush(sb, minLen);
        }

        Flush(sb, minLen);
    }

    static void ExtractUnicodeUtf16(byte[] data, int minLen)
    {
        int start = -1;
        int count = 0;

        for (int i = 0; i < data.Length - 1; i += 2)
        {
            ushort val = BitConverter.ToUInt16(data, i);

            if (val == 0x0000 || (val < 0x20 && val != 0x20))
            {
                FlushUnicode(data, start, count, minLen);
                start = -1;
                count = 0;
                continue;
            }

            if (start == -1)
                start = i;

            count++;
        }

        FlushUnicode(data, start, count, minLen);
    }

    static void Flush(StringBuilder sb, int minLen)
    {
        if (sb.Length >= minLen)
        {
            string s = sb.ToString();
            if (seen.Add(s))
            {
                writer.WriteLine(s);
                TryParseDeviceExe(s);
                TryParseQuery(s);
            }
        }
        sb.Clear();
    }

    static void FlushUnicode(byte[] data, int start, int count, int minLen)
    {
        if (start == -1 || count < minLen)
            return;

        string s = Encoding.Unicode.GetString(data, start, count * 2);
        if (seen.Add(s))
        {
            writer.WriteLine(s);
            TryParseDeviceExe(s);
            TryParseQuery(s);
        }
    }

    static void TryParseDeviceExe(string s)
    {
        if (!s.StartsWith(@"\Device\HarddiskVolume", StringComparison.OrdinalIgnoreCase))
            return;

        int exe = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exe == -1)
            return;

        string devicePath = s.Substring(0, exe + 4);
        string dosPath = ConvertDevicePathToDosPath(devicePath);

        if (parsedSeen.Add(dosPath))
            parsedWriter.WriteLine(dosPath);
    }

    static void TryParseQuery(string s)
    {
        int start = s.IndexOf("!!");
        if (start == -1) return;

        start += 2;
        int exeEnd = s.IndexOf('!', start);
        if (exeEnd == -1) return;

        string exeName = s.Substring(start, exeEnd - start);
        if (!exeName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return;

        int dateStart = exeEnd + 1;
        int dateEnd = s.IndexOf('!', dateStart);
        if (dateEnd == -1) return;

        string date = s.Substring(dateStart, dateEnd - dateStart);

        string fullMatch = s.Substring(start - 2, dateEnd - (start - 2) + 1);

        if (querySeen.Add(fullMatch))
            queryWriter.WriteLine(fullMatch);
    }

    static bool IsReadable(uint protect) =>
        protect == PAGE_READONLY ||
        protect == PAGE_READWRITE ||
        protect == PAGE_EXECUTE_READ ||
        protect == PAGE_EXECUTE_READWRITE;

    #region WinAPI

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern uint QueryDosDevice(
        string lpDeviceName,
        StringBuilder lpTargetPath,
        int ucchMax);

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr baseAddress,
        byte[] buffer,
        int size,
        out int bytesRead);

    [DllImport("kernel32.dll")]
    static extern int VirtualQueryEx(
        IntPtr hProcess,
        IntPtr address,
        out MEMORY_BASIC_INFORMATION info,
        uint size);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);

    [DllImport("advapi32.dll")]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll")]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY = 0x0008;
    const string SE_DEBUG_NAME = "SeDebugPrivilege";
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_READONLY = 0x02;
    const uint PAGE_READWRITE = 0x04;
    const uint PAGE_EXECUTE_READ = 0x20;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    [StructLayout(LayoutKind.Sequential)]
    struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    #endregion
}