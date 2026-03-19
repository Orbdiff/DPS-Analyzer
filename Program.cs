using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

class Program
{
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_READ = 0x0010;
    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY = 0x0008;
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    const string SE_DEBUG_NAME = "SeDebugPrivilege";
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_READONLY = 0x02;
    const uint PAGE_READWRITE = 0x04;
    const uint PAGE_EXECUTE_READ = 0x20;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    static readonly HashSet<string> seen = new HashSet<string>();
    static readonly HashSet<string> parsedSeen = new HashSet<string>();
    static readonly HashSet<string> querySeen = new HashSet<string>();
    static readonly HashSet<string> modExtSeen = new HashSet<string>();

    static readonly Dictionary<string, string> deviceMap =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    static readonly Regex modExtRegex = new Regex(@"^\\device\\harddiskvolume[0-99]\\((?!exe).)*$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    static void Main()
    {
        BuildDeviceMap();

        if (!ElevateDebugPrivilege())
        {
            Console.WriteLine("[-] Failed to elevate debug privileges");
            return;
        }

        int pid = GetDpsPid();
        if (pid == 0)
        {
            Console.WriteLine("[-] DPS process not found");
            return;
        }

        Console.WriteLine($"[+] DPS PID: {pid}");

        IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (hProcess == IntPtr.Zero)
        {
            Console.WriteLine("[-] Failed to open process (admin privileges required)");
            return;
        }

        var rawStrings = new List<string>();
        var parsedPaths = new List<string>();
        var queryMatches = new List<string>();
        var modExtMatches = new List<string>();

        ScanMemory(hProcess, rawStrings, parsedPaths, queryMatches, modExtMatches);
        CloseHandle(hProcess);

        if (rawStrings.Count > 0)
        {
            File.WriteAllLines("dps_strings.txt", rawStrings, Encoding.UTF8);
            Console.WriteLine("[+] dps_strings.txt");
        }

        if (parsedPaths.Count > 0)
        {
            File.WriteAllLines("dps-parsed-results.txt", parsedPaths, Encoding.UTF8);
            Console.WriteLine("[+] dps-parsed-results.txt");
        }

        if (queryMatches.Count > 0)
        {
            File.WriteAllLines("dps-query-results.txt", queryMatches, Encoding.UTF8);
            Console.WriteLine("[+] dps-query-results.txt");
        }

        if (modExtMatches.Count > 0)
        {
            File.WriteAllLines("dps-modified-extension.txt", modExtMatches, Encoding.UTF8);
            Console.WriteLine("[+] dps-modified-extension.txt");
        }

        var suspiciousLines = BuildSuspiciousResults(queryMatches);
        if (suspiciousLines.Count > 0)
        {
            File.WriteAllLines("dps-suspicious-results.txt", suspiciousLines, Encoding.UTF8);
            Console.WriteLine("[+] dps-suspicious-results.txt");
        }

        var parsedPathLines = BuildParsedPaths(parsedPaths, suspiciousLines);
        if (parsedPathLines.Count > 0)
        {
            File.WriteAllLines("dps-parsed-paths.txt", parsedPathLines, Encoding.UTF8);
            Console.WriteLine("[+] dps-parsed-paths.txt");
        }

        var fullSigcheck = BuildFullSigcheck(parsedPaths);
        if (fullSigcheck.Count > 0)
        {
            File.WriteAllLines("dps-full-sigcheck-executables.txt", fullSigcheck, Encoding.UTF8);
            Console.WriteLine("[+] dps-full-sigcheck-executables.txt");
        }

        var unsigned = new List<string>();
        var notFound = new List<string>();
        foreach (var line in fullSigcheck)
        {
            if (line.StartsWith("Unsigned |") || line.StartsWith("Fake Sig |") || line.StartsWith("Local Sig |"))
                unsigned.Add(line);
            else if (line.StartsWith("NotFound |"))
                notFound.Add(line);
        }

        if (unsigned.Count > 0)
        {
            File.WriteAllLines("dps-full-unsigned-executables.txt", unsigned, Encoding.UTF8);
            Console.WriteLine("[+] dps-full-unsigned-executables.txt");
        }

        if (notFound.Count > 0)
        {
            File.WriteAllLines("dps-full-notfound-executables.txt", notFound, Encoding.UTF8);
            Console.WriteLine("[+] dps-full-notfound-executables.txt");
        }

        Console.WriteLine("\n[+] All files created successfully.");
        System.Threading.Thread.Sleep(3000);
        Environment.Exit(0);
    }

    static void ScanMemory(IntPtr hProcess,
        List<string> rawStrings,
        List<string> parsedPaths,
        List<string> queryMatches,
        List<string> modExtMatches)
    {
        ulong address = 0;
        MEMORY_BASIC_INFORMATION mbi;

        while (VirtualQueryEx(hProcess, (IntPtr)address, out mbi,
            (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0)
        {
            if (mbi.State == MEM_COMMIT && IsReadable(mbi.Protect))
            {
                byte[] buffer = new byte[(int)mbi.RegionSize];
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, buffer.Length, out _))
                {
                    ExtractAscii(buffer, 5, rawStrings, parsedPaths, queryMatches, modExtMatches);
                    ExtractUnicodeUtf16(buffer, 5, rawStrings, parsedPaths, queryMatches, modExtMatches);
                }
            }

            address += (ulong)mbi.RegionSize;
        }
    }

    static void ExtractAscii(byte[] data, int minLen,
        List<string> rawStrings, List<string> parsedPaths,
        List<string> queryMatches, List<string> modExtMatches)
    {
        var sb = new StringBuilder();
        foreach (byte b in data)
        {
            if (b >= 32 && b <= 126)
                sb.Append((char)b);
            else
            {
                ProcessString(sb, minLen, rawStrings, parsedPaths, queryMatches, modExtMatches);
                sb.Clear();
            }
        }
        ProcessString(sb, minLen, rawStrings, parsedPaths, queryMatches, modExtMatches);
    }

    static void ExtractUnicodeUtf16(byte[] data, int minLen,
        List<string> rawStrings, List<string> parsedPaths,
        List<string> queryMatches, List<string> modExtMatches)
    {
        int start = -1;
        int count = 0;

        for (int i = 0; i < data.Length - 1; i += 2)
        {
            ushort val = BitConverter.ToUInt16(data, i);

            if (val == 0x0000 || (val < 0x20 && val != 0x20))
            {
                if (start != -1 && count >= minLen)
                {
                    string s = Encoding.Unicode.GetString(data, start, count * 2);
                    if (seen.Add(s))
                        Parse(s, rawStrings, parsedPaths, queryMatches, modExtMatches);
                }
                start = -1;
                count = 0;
                continue;
            }

            if (start == -1) start = i;
            count++;
        }

        if (start != -1 && count >= minLen)
        {
            string s = Encoding.Unicode.GetString(data, start, count * 2);
            if (seen.Add(s))
                Parse(s, rawStrings, parsedPaths, queryMatches, modExtMatches);
        }
    }

    static void ProcessString(StringBuilder sb, int minLen,
        List<string> rawStrings, List<string> parsedPaths,
        List<string> queryMatches, List<string> modExtMatches)
    {
        if (sb.Length >= minLen)
        {
            string s = sb.ToString();
            if (seen.Add(s))
                Parse(s, rawStrings, parsedPaths, queryMatches, modExtMatches);
        }
    }

    static void Parse(string s,
        List<string> rawStrings, List<string> parsedPaths,
        List<string> queryMatches, List<string> modExtMatches)
    {
        rawStrings.Add(s);
        TryParseDeviceExe(s, parsedPaths);
        TryParseQuery(s, queryMatches);
        TryParseModifiedExtension(s, modExtMatches);
    }

    static void TryParseDeviceExe(string s, List<string> parsedPaths)
    {
        if (!s.StartsWith(@"\Device\HarddiskVolume", StringComparison.OrdinalIgnoreCase)) return;

        int exeIndex = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIndex == -1) return;

        string dosPath = ConvertDevicePathToDosPath(s.Substring(0, exeIndex + 4));
        if (parsedSeen.Add(dosPath))
            parsedPaths.Add(dosPath);
    }

    static void TryParseQuery(string s, List<string> queryMatches)
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

        string fullMatch = s.Substring(start - 2, dateEnd - (start - 2) + 1);
        if (querySeen.Add(fullMatch))
            queryMatches.Add(fullMatch);
    }

    static void TryParseModifiedExtension(string s, List<string> modExtMatches)
    {
        if (!modExtRegex.IsMatch(s)) return;

        string dosPath = ConvertDevicePathToDosPath(s);
        if (modExtSeen.Add(dosPath))
            modExtMatches.Add(dosPath);
    }

    static List<string> BuildSuspiciousResults(List<string> queryMatches)
    {
        var exeDates = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var line in queryMatches)
        {
            string exeName = ExtractField(line, 0);
            string date = ExtractField(line, 1);
            if (string.IsNullOrEmpty(exeName) || string.IsNullOrEmpty(date)) continue;

            if (!exeDates.TryGetValue(exeName, out var dates))
            {
                dates = new HashSet<string>();
                exeDates[exeName] = dates;
            }
            dates.Add(date);
        }

        var result = new List<string>();
        foreach (var kv in exeDates)
            if (kv.Value.Count > 1)
                foreach (var date in kv.Value)
                    result.Add($"!!{kv.Key}!{date}!");

        return result;
    }

    static List<string> BuildParsedPaths(List<string> parsedPaths, List<string> suspiciousLines)
    {
        var suspiciousExes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in suspiciousLines)
        {
            string exe = ExtractField(line, 0);
            if (!string.IsNullOrEmpty(exe))
                suspiciousExes.Add(exe);
        }

        var result = new List<string>();
        foreach (var line in parsedPaths)
        {
            int lastSlash = line.LastIndexOfAny(new[] { '\\', '/' });
            if (lastSlash == -1) continue;

            string exe = line.Substring(lastSlash + 1);
            if (!suspiciousExes.Contains(exe)) continue;

            result.Add($"{GetSignatureStatus(line)} | {line}");
        }

        return result;
    }

    static List<string> BuildFullSigcheck(List<string> parsedPaths)
    {
        var result = new List<string>();
        foreach (var line in parsedPaths)
            result.Add($"{GetSignatureStatus(line)} | {line}");
        return result;
    }

    static string ExtractField(string line, int fieldIndex)
    {
        int start = line.IndexOf("!!");
        if (start == -1) return string.Empty;

        start += 2;
        int end = line.IndexOf('!', start);
        if (end == -1) return string.Empty;

        if (fieldIndex == 0)
        {
            string exe = line.Substring(start, end - start);
            return exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? exe : string.Empty;
        }

        int dateStart = end + 1;
        int dateEnd = line.IndexOf('!', dateStart);
        if (dateEnd == -1) return string.Empty;

        return line.Substring(dateStart, dateEnd - dateStart);
    }

    static string GetSignatureStatus(string filePath)
    {
        if (!File.Exists(filePath)) return "NotFound";

        try
        {
#pragma warning disable SYSLIB0057
            X509Certificate cert = X509Certificate2.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
            X509Certificate2 cert2 = new X509Certificate2(cert);

            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags =
                X509VerificationFlags.AllowUnknownCertificateAuthority |
                X509VerificationFlags.IgnoreNotTimeValid;

            bool isValid = chain.Build(cert2);

            if (isValid && chain.ChainElements.Count > 1) return "Signed";
            if (cert2.Subject == cert2.Issuer) return "Local Sig";
            return "Fake Sig";
        }
        catch
        {
            return "Unsigned";
        }
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
            if (path.StartsWith(kv.Key, StringComparison.OrdinalIgnoreCase))
                return kv.Value + path.Substring(kv.Key.Length);
        return path;
    }

    static int GetDpsPid()
    {
        using var searcher = new ManagementObjectSearcher(
            "SELECT ProcessId FROM Win32_Service WHERE Name='DPS'");

        foreach (ManagementObject obj in searcher.Get())
            return Convert.ToInt32(obj["ProcessId"]);

        return 0;
    }

    static bool ElevateDebugPrivilege()
    {
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle,
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr hToken))
            return false;

        if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, out LUID luid))
        {
            CloseHandle(hToken);
            return false;
        }

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges = new LUID_AND_ATTRIBUTES[1];
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        bool result = AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        CloseHandle(hToken);
        return result;
    }

    static bool IsReadable(uint protect) =>
        protect == PAGE_READONLY ||
        protect == PAGE_READWRITE ||
        protect == PAGE_EXECUTE_READ ||
        protect == PAGE_EXECUTE_READWRITE;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr baseAddress, byte[] buffer, int size, out int bytesRead);

    [DllImport("kernel32.dll")]
    static extern int VirtualQueryEx(IntPtr hProcess, IntPtr address, out MEMORY_BASIC_INFORMATION info, uint size);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);

    [DllImport("advapi32.dll")]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll")]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

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
}
