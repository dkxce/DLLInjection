//
//      DO NOT BUILD `AnyCPU`
// in AnyCPU build DLL will not work!
//   !!! Build only x86 or x64 !!!
//
//
// Original Manual at:
//   https://www.sites.google.com/site/robertgiesecke/Home/uploads/unmanagedexports
// NuGet:
//   https://www.nuget.org/packages/UnmanagedExports
// Build on article:
//   https://www.c-sharpcorner.com/article/export-managed-code-as-unmanaged/
//

//
// Это библиотека C#, которая экспортирует функции для других программ не .Net
//

using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using RGiesecke.DllExport;

using System.Windows.Forms;

namespace injlib
{
    internal static class UnmanagedExports
    {
        // C++    -- typedef void (__cdecl * TestFunc)();
        // python -- _cdll.Test()
        // delphi -- procedure Test(); cdecl; external 'UnmanagedExports.dll';
        [DllExport("Test", CallingConvention = CallingConvention.Cdecl)]
        static void Test()
        {
            MessageBox.Show("Test Called");
        }

        // C++    -- typedef void* (__cdecl * ShowMessage)(char*);
        // python -- _cdll.ShowMessage(c_char_p(b"Passed by Python"))
        // delphi -- procedure ShowMessage(str: PChar); cdecl; external 'UnmanagedExports.dll';
        [DllExport("ShowMessage", CallingConvention = CallingConvention.Cdecl)]
        static void ShowMessage(string message)
        {
            MessageBox.Show(message);
        }

        // C++    -- typedef char* (__cdecl * GetLibNameFunc)();
        // python -- c_char_p(_cdll.GetLibName())
        // delphi -- function GetLibName(): PChar; cdecl; external 'UnmanagedExports.dll';
        [DllExport("GetLibName", CallingConvention = CallingConvention.Cdecl)]
        static string GetLibName()
        {
            return "injlib.dll GetLibName callback";
        }

    }

    // INJECT DLL TO ANOTHER PROCESS
    // -- locate or load dll in another process
    // -- and run dll function as thread in another process
    public class InjectDLL
    {
        public static class PrivilegeManager
        {
            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool OpenProcessToken(
                IntPtr ProcessHandle,
                UInt32 DesiredAccess, out IntPtr TokenHandle);

            private static uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
            private static uint STANDARD_RIGHTS_READ = 0x00020000;
            private static uint TOKEN_ASSIGN_PRIMARY = 0x0001;
            private static uint TOKEN_DUPLICATE = 0x0002;
            private static uint TOKEN_IMPERSONATE = 0x0004;
            private static uint TOKEN_QUERY = 0x0008;
            private static uint TOKEN_QUERY_SOURCE = 0x0010;
            private static uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
            private static uint TOKEN_ADJUST_GROUPS = 0x0040;
            private static uint TOKEN_ADJUST_DEFAULT = 0x0080;
            private static uint TOKEN_ADJUST_SESSIONID = 0x0100;
            private static uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
            private static uint TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
                TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
                TOKEN_ADJUST_SESSIONID);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetCurrentProcess();

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool LookupPrivilegeValue(
                string lpSystemName,
                string lpName,
                out LUID lpLuid);

            #region Privelege constants

            public const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
            public const string SE_AUDIT_NAME = "SeAuditPrivilege";
            public const string SE_BACKUP_NAME = "SeBackupPrivilege";
            public const string SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege";
            public const string SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege";
            public const string SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege";
            public const string SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege";
            public const string SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege";
            public const string SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege";
            public const string SE_DEBUG_NAME = "SeDebugPrivilege";
            public const string SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege";
            public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
            public const string SE_INC_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege";
            public const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
            public const string SE_INC_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege";
            public const string SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege";
            public const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";
            public const string SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege";
            public const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";
            public const string SE_PROF_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";
            public const string SE_RELABEL_NAME = "SeRelabelPrivilege";
            public const string SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege";
            public const string SE_RESTORE_NAME = "SeRestorePrivilege";
            public const string SE_SECURITY_NAME = "SeSecurityPrivilege";
            public const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
            public const string SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege";
            public const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";
            public const string SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege";
            public const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";
            public const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";
            public const string SE_TCB_NAME = "SeTcbPrivilege";
            public const string SE_TIME_ZONE_NAME = "SeTimeZonePrivilege";
            public const string SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege";
            public const string SE_UNDOCK_NAME = "SeUndockPrivilege";
            public const string SE_UNSOLICITED_INPUT_NAME = "SeUnsolicitedInputPrivilege";
            #endregion

            [StructLayout(LayoutKind.Sequential)]
            public struct LUID
            {
                public UInt32 LowPart;
                public Int32 HighPart;
            }

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern bool CloseHandle(IntPtr hHandle);

            public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
            public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
            public const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
            public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;

            [StructLayout(LayoutKind.Sequential)]
            public struct TOKEN_PRIVILEGES
            {
                public UInt32 PrivilegeCount;
                public LUID Luid;
                public UInt32 Attributes;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct LUID_AND_ATTRIBUTES
            {
                public LUID Luid;
                public UInt32 Attributes;
            }

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool AdjustTokenPrivileges(
                IntPtr TokenHandle,
               [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges,
               ref TOKEN_PRIVILEGES NewState,
               UInt32 Zero,
               IntPtr Null1,
               IntPtr Null2);

            /// <summary>
            /// Меняет привилегию
            /// </summary>
            /// <param name="PID">ID процесса</param>
            /// <param name="privelege">Привилегия</param>
            public static void SetPrivilege(
                IntPtr PID,
                string privilege)
            {
                IntPtr hToken;
                LUID luidSEDebugNameValue;
                TOKEN_PRIVILEGES tkpPrivileges;

                if (!OpenProcessToken(PID, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
                {
                    throw new Exception("Произошла ошибка при выполнении OpenProcessToken(). Код ошибки "
                        + Marshal.GetLastWin32Error());
                }

                if (!LookupPrivilegeValue(null, privilege, out luidSEDebugNameValue))
                {
                    CloseHandle(hToken);
                    throw new Exception("Произошла ошибка при выполнении LookupPrivilegeValue(). Код ошибки "
                        + Marshal.GetLastWin32Error());
                }

                tkpPrivileges.PrivilegeCount = 1;
                tkpPrivileges.Luid = luidSEDebugNameValue;
                tkpPrivileges.Attributes = SE_PRIVILEGE_ENABLED;

                if (!AdjustTokenPrivileges(hToken, false, ref tkpPrivileges, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    throw new Exception("Произошла ошибка при выполнении LookupPrivilegeValue(). Код ошибки :"
                        + Marshal.GetLastWin32Error());
                }
                CloseHandle(hToken);
            }
        }

        #region // kernel32.dll methods
        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, UIntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, Int32 bInheritHandle, Int32 dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern Int32 CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, string lpBuffer, UIntPtr nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out, MarshalAs(UnmanagedType.AsAny)] object lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern Int32 WaitForSingleObject(IntPtr handle, Int32 milliseconds);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LoadLibrary(string dllToLoad);

        [DllImport("kernel32.dll")]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string moduleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
        public static extern UIntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [DllImport("kernel32.dll", EntryPoint = "GetProcAddress")]
        public static extern IntPtr GetProcAddress0(IntPtr hModule, string procedureName);
        #endregion // kernel32.dll methods

        #region // static methods
        public static Int32 GetProcessId(string processName)
        {
            System.Diagnostics.Process[] ProcList = System.Diagnostics.Process.GetProcessesByName(processName);
            if ((ProcList == null) || (ProcList.Length == 0))
                ProcList = System.Diagnostics.Process.GetProcessesByName(System.IO.Path.GetFileNameWithoutExtension(processName));
            if ((ProcList == null) || (ProcList.Length == 0)) return 0;
            return ProcList[0].Id;
        }

        public static IntPtr GetProcessDLLModule(string strProcessName, String strDLLName)
        {
            strDLLName = System.IO.Path.GetFileName(strDLLName);
            System.Diagnostics.Process[] procs = System.Diagnostics.Process.GetProcessesByName(strProcessName);
            if ((procs == null) || (procs.Length == 0)) return IntPtr.Zero;
            foreach (System.Diagnostics.ProcessModule pm in procs[0].Modules)
                if (pm.ModuleName == strDLLName)
                    return pm.BaseAddress;
            return IntPtr.Zero;
        }

        public static IntPtr GetProcessDLLModule(int processId, string strDLLName)
        {
            strDLLName = System.IO.Path.GetFileName(strDLLName);
            System.Diagnostics.Process proc = System.Diagnostics.Process.GetProcessById(processId);
            foreach (System.Diagnostics.ProcessModule pm in proc.Modules)
                if (pm.ModuleName == strDLLName)
                    return pm.BaseAddress;
            return IntPtr.Zero;
        }

        public static IntPtr GetProcessDLLProcAddress(IntPtr pModule, string ModuleName, string ProcName)
        {
            IntPtr pTrd = IntPtr.Zero;
            IntPtr pDLL = LoadLibrary(ModuleName);
            if (pDLL != IntPtr.Zero)
            {
                pTrd = GetProcAddress0(pDLL, ProcName);
                FreeLibrary(pDLL);
            };
            return (IntPtr)((uint)pTrd - (uint)pDLL + (uint)pModule);
        }

        public static bool RunDLLFuncAsThread(int processId, IntPtr addr, ref string exStr)
        {
            return RunDLLFuncAsThread(processId, addr, ref exStr, 65536);
        }

        /// <summary>
        ///     C++ -- typedef void (__stdcall * ProcName)(char*);
        /// </summary>
        /// <param name="processId">ProcessID</param>
        /// <param name="addr">Address of Function / Entry Point</param>
        /// <param name="exStr">Pointer to a string / char*</param>
        /// <param name="maxBuffSize">max string length</param>
        /// <returns></returns>
        public static bool RunDLLFuncAsThread(int processId, IntPtr addr, ref string exStr, int maxBuffSize)
        {
            IntPtr hProcess = (IntPtr)OpenProcess(0x1F0FFF, 1, processId);
            if (hProcess == IntPtr.Zero) return false;

            IntPtr bytesout;
            Int32 LenWrite = (int)maxBuffSize;
            IntPtr AllocMem = (IntPtr)VirtualAllocEx(hProcess, (IntPtr)null, (uint)LenWrite, 0x1000, 0x40);
            WriteProcessMemory(hProcess, AllocMem, exStr, (UIntPtr)LenWrite, out bytesout);
            UIntPtr Injector = (UIntPtr)((int)addr);
            // hProcess, attr, stack size, funcAddr, obj pointer, flags, bytesout
            IntPtr hThread = (IntPtr)CreateRemoteThread(hProcess, (IntPtr)null, 0, Injector, AllocMem, 0, out bytesout);
            int Result = WaitForSingleObject(hThread, 10 * 1000);
            if (Result == 0x00000080L || Result == 0x00000102L || Result == 0xFFFFFFFF)
            {
                if (hThread != null) CloseHandle(hThread);
                return false;
            };

            System.Threading.Thread.Sleep(1000);

            IntPtr nbr;
            char[] rb = new char[LenWrite];
            ReadProcessMemory(hProcess, AllocMem, rb, LenWrite, out nbr);
            string txt = new string(rb);
            int ze = txt.IndexOf('\0');
            if (ze > 0) txt = txt.Substring(0, ze);
            exStr = txt;

            VirtualFreeEx(hProcess, AllocMem, (UIntPtr)LenWrite, 0x8000);
            if (hThread != null)
            {
                CloseHandle(hThread);
                return true;
            }
            else
                return false;
        }

        public static bool RunDLLFuncAsThread(int processId, IntPtr funcAddr)
        {
            IntPtr hProcess = (IntPtr)OpenProcess(0x1F0FFF, 1, processId);
            if (hProcess == IntPtr.Zero) return false;

            IntPtr bytesout;
            UIntPtr Injector = (UIntPtr)((int)funcAddr);
            IntPtr hThread = (IntPtr)CreateRemoteThread(hProcess, (IntPtr)null, 0, Injector, IntPtr.Zero, 0, out bytesout);
            int Result = WaitForSingleObject(hThread, 10 * 1000);
            if (Result == 0x00000080L || Result == 0x00000102L || Result == 0xFFFFFFFF)
            {
                if (hThread != null) CloseHandle(hThread);
                return false;
            };

            System.Threading.Thread.Sleep(1000);

            if (hThread != null)
            {
                CloseHandle(hThread);
                return true;
            }
            else
                return false;
        }

        /// <summary>
        ///     C++ -- typedef void (__stdcall * ProcName)(STRUCT*);
        /// </summary>
        /// <param name="processId">ProcessID</param>
        /// <param name="funcAddr">Address of Function / Entry Point</param>
        /// <param name="data">STRUCT as byte array</param>
        /// <returns></returns>
        public static bool RunDLLFuncAsThread(int processId, IntPtr funcAddr, ref byte[] data)
        {
            IntPtr hProcess = (IntPtr)OpenProcess(0x1F0FFF, 1, processId);
            if (hProcess == IntPtr.Zero) return false;

            IntPtr bytesout;
            IntPtr AllocMem = (IntPtr)VirtualAllocEx(hProcess, (IntPtr)null, (uint)data.Length, 0x1000, 0x40);
            WriteProcessMemory(hProcess, AllocMem, data, data.Length, out bytesout);
            UIntPtr Injector = (UIntPtr)((int)funcAddr);
            // hProcess, attr, stack size, funcAddr, obj pointer, flags, bytesout
            IntPtr hThread = (IntPtr)CreateRemoteThread(hProcess, (IntPtr)null, 0, Injector, AllocMem, 0, out bytesout);
            int Result = WaitForSingleObject(hThread, 10 * 1000);
            if (Result == 0x00000080L || Result == 0x00000102L || Result == 0xFFFFFFFF)
            {
                if (hThread != null) CloseHandle(hThread);
                return false;
            };

            System.Threading.Thread.Sleep(1000);

            IntPtr nbr;
            ReadProcessMemory(hProcess, AllocMem, data, data.Length, out nbr);

            VirtualFreeEx(hProcess, AllocMem, (UIntPtr)data.Length, 0x8000);
            if (hThread != null)
            {
                CloseHandle(hThread);
                return true;
            }
            else
                return false;
        }

        public static bool InjectDLLToProc(IntPtr hProcess, string strDLLName)
        {
            IntPtr bytesout;
            Int32 LenWrite = strDLLName.Length + 1;
            IntPtr AllocMem = (IntPtr)VirtualAllocEx(hProcess, (IntPtr)null, (uint)LenWrite, 0x1000, 0x40);
            WriteProcessMemory(hProcess, AllocMem, strDLLName, (UIntPtr)LenWrite, out bytesout);
            UIntPtr Injector = (UIntPtr)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            IntPtr hThread = (IntPtr)CreateRemoteThread(hProcess, (IntPtr)null, 0, Injector, AllocMem, 0, out bytesout);
            int Result = WaitForSingleObject(hThread, 10 * 1000);
            if (Result == 0x00000080L || Result == 0x00000102L || Result == 0xFFFFFFFF)
            {
                if (hThread != null) CloseHandle(hThread);
                return false;
            };

            System.Threading.Thread.Sleep(1000);
            VirtualFreeEx(hProcess, AllocMem, (UIntPtr)0, 0x8000);
            if (hThread != null)
            {
                CloseHandle(hThread);
                return true;
            }
            else
                return false;
        }

        public static bool InjectDLLToProc(int processId, string strDLLName)
        {
            IntPtr hProcess = (IntPtr)OpenProcess(0x1F0FFF, 1, processId);
            if (hProcess == IntPtr.Zero) return false;
            return InjectDLLToProc(hProcess, strDLLName);
        }

        public static bool InjectDLLToProc(string strProcessName, string strDLLName)
        {
            Int32 ProcID = GetProcessId(strProcessName);
            if (ProcID == 0) return false;
            IntPtr hProcess = (IntPtr)OpenProcess(0x1F0FFF, 1, ProcID);
            if (hProcess == IntPtr.Zero) return false;
            return InjectDLLToProc(hProcess, strDLLName);
        }
        #endregion // static methods

        // object //

        private IntPtr _ModuleHandle = IntPtr.Zero;
        private string _ModuleName = String.Empty;
        private string _ProcessName = String.Empty;
        private int _ProcessID = 0;
        private bool _RunIfNot = false;
        private bool _KillOnDeInit = false;

        // Find Module/DLL in Process
        /// <summary>
        ///     Find Module/DLL in Process
        /// </summary>
        /// <param name="processName"></param>
        /// <param name="dllName"></param>
        public void Init(string processName, string dllName)
        {
            Init(processName, 0, dllName, false);
        }

        // Find Module/DLL in Process and run process if it doesn't
        /// <summary>
        ///     Find Module/DLL in Process and run process if it doesn't
        /// </summary>
        /// <param name="processName"></param>
        /// <param name="dllName"></param>
        public void InitRun(string processName, string dllName)
        {
            Init(processName, 0, dllName, true);
        }

        // Find Module/DLL in Process by ProcessID
        /// <summary>
        ///     Find Module/DLL in Process by ProcessID
        /// </summary>
        /// <param name="processId"></param>
        /// <param name="dllName"></param>
        public void Init(int processId, string dllName)
        {
            Init(string.Empty, processId, dllName, false);
        }

        // Find Module/DLL in Process by name or ProcessID
        /// <summary>
        ///     Find Module/DLL in Process by name or ProcessID
        /// </summary>
        /// <param name="processName"></param>
        /// <param name="processId"></param>
        /// <param name="dllName"></param>
        public void Init(string processName, int processId, string dllName)
        {
            Init(processName, processId, dllName, false);
        }

        // Find Module/DLL in Process by Exe Name and run process if it doesn't
        /// <summary>
        ///     Find Module/DLL in Process by Exe Name and run process if it doesn't
        /// </summary>
        /// <param name="exeName"></param>
        /// <param name="exeCmdArguments"></param>
        /// <param name="dllName"></param>
        public void InitRun(string exeName, string exeCmdArguments, string dllName)
        {
            _RunIfNot = true;
            _ModuleName = dllName;
            _ProcessName = System.IO.Path.GetFileNameWithoutExtension(exeName);
            _ProcessID = String.IsNullOrEmpty(_ProcessName) ? 0 : GetProcessId(_ProcessName);

            if ((_ProcessID == 0) && (_RunIfNot) && (!String.IsNullOrEmpty(_ProcessName)))
            {
                System.Diagnostics.Process proc = System.Diagnostics.Process.Start(exeName, exeCmdArguments);
                if (proc != null) _ProcessID = proc.Id;
            };

            _ModuleHandle = _ProcessID == 0 ? IntPtr.Zero : GetProcessDLLModule(_ProcessID, _ModuleName);
            if ((_ProcessID != 0) && (_ModuleHandle == IntPtr.Zero))
            {
                InjectDLL.InjectDLLToProc(_ProcessID, _ModuleName);
                _ModuleHandle = InjectDLL.GetProcessDLLModule(_ProcessID, _ModuleName);

                // PrivilegeManager.SetPrivilege(System.Diagnostics.Process.GetCurrentProcess().Handle, InjectDLL.PrivilegeManager.SE_DEBUG_NAME);
            };
        }

        private void Init(string processName, int processId, string dllName, bool RunIfNot)
        {
            _RunIfNot = RunIfNot;
            _ModuleName = dllName;
            _ProcessName = processName;
            _ProcessID = processId == 0 ? (String.IsNullOrEmpty(_ProcessName) ? 0 : GetProcessId(_ProcessName)) : processId;

            if ((_ProcessID == 0) && (_RunIfNot) && (!String.IsNullOrEmpty(_ProcessName)))
            {
                string fileName = _ProcessName;
                if (!fileName.ToLower().EndsWith(".exe")) fileName += ".exe";
                if (!File.Exists(fileName))
                    fileName = GetCurrentDir() + @"\" + fileName;
                if (File.Exists(fileName))
                {
                    System.Diagnostics.Process proc = System.Diagnostics.Process.Start(fileName);
                    if (proc != null) _ProcessID = proc.Id;
                };
            };

            _ModuleHandle = _ProcessID == 0 ? IntPtr.Zero : GetProcessDLLModule(_ProcessID, _ModuleName);
            if ((_ProcessID != 0) && (_ModuleHandle == IntPtr.Zero))
            {
                InjectDLL.InjectDLLToProc(_ProcessID, _ModuleName);
                _ModuleHandle = InjectDLL.GetProcessDLLModule(_ProcessID, _ModuleName);

                // PrivilegeManager.SetPrivilege(System.Diagnostics.Process.GetCurrentProcess().Handle, InjectDLL.PrivilegeManager.SE_DEBUG_NAME);
            };
        }

        // Get Initializated Process ID
        public int ProcessID
        {
            get
            {
                return _ProcessID;
            }
        }

        // Get Initializated Module/DLL Handle
        public IntPtr ModuleHandle
        {
            get
            {
                return _ModuleHandle;
            }
        }

        // Get Initializated Module/DLL Name
        public string ModuleName
        {
            get
            {
                return _ModuleName;
            }
        }

        // Get Initializated Process Name
        public string ProcessName
        {
            get
            {
                return _ProcessName;
            }
        }

        // Preinit -- Run If Not
        public bool RunIfNot
        {
            get
            {
                return _RunIfNot;
            }
            set
            {
                _RunIfNot = value;
            }
        }

        // PreDeInit - Kill on DeInit
        public bool KillOnDeInit
        {
            get
            {
                return _KillOnDeInit;
            }
            set
            {
                _KillOnDeInit = value;
            }
        }

        // Get Address of Procedure/Function/Method in Initializated Module of Process
        public IntPtr GetProcAddr(string ProcName)
        {
            if ((_ProcessID == 0) || (_ModuleHandle == IntPtr.Zero)) return IntPtr.Zero;
            return GetProcessDLLProcAddress(_ModuleHandle, _ModuleName, ProcName);
        }

        // Get Addresses of Procedures/Functions/Methods in Initializated Module of Process
        public IntPtr[] GetProcAddr(string[] ProcNames)
        {
            if ((_ProcessID == 0) || (_ModuleHandle == IntPtr.Zero) || (ProcNames == null) || (ProcNames.Length == 0)) return null;
            IntPtr[] res = new IntPtr[ProcNames.Length];

            IntPtr pDLL = LoadLibrary(ModuleName);
            if (pDLL != IntPtr.Zero)
            {
                for (int i = 0; i < ProcNames.Length; i++)
                {
                    IntPtr pTrd = GetProcAddress0(pDLL, ProcNames[i]);
                    res[i] = (IntPtr)((uint)pTrd - (uint)pDLL + (uint)_ModuleHandle);
                };
                FreeLibrary(pDLL);
            };
            return res;
        }

        // Get Address of Procedure/Function/Method in Initializated Module of Process
        public IntPtr this[string ProcName]
        {
            get
            {
                return GetProcAddr(ProcName);
            }
        }

        // Get Addresses of Procedures/Functions/Methods in Initializated Module of Process
        public IntPtr[] this[string[] ProcNames]
        {
            get
            {
                return GetProcAddr(ProcNames);
            }
        }

        public bool RunThread(IntPtr procAddr)
        {
            if ((_ProcessID == 0) || (_ModuleHandle == IntPtr.Zero) || (procAddr == IntPtr.Zero)) return false;
            return RunDLLFuncAsThread(_ProcessID, procAddr);
        }

        // Run Procedure/Function/Method in Initializated Module of Process as Thread with string/char* as parameter
        public bool RunThread(IntPtr procAddr, ref string exStr)
        {
            if ((_ProcessID == 0) || (_ModuleHandle == IntPtr.Zero) || (procAddr == IntPtr.Zero)) return false;
            return RunDLLFuncAsThread(_ProcessID, procAddr, ref exStr);
        }

        // Run Procedure/Function/Method in Initializated Module of Process as Thread with string/char* as parameter
        public bool RunThread(IntPtr procAddr, ref string exStr, int maxBuffSize)
        {
            if ((_ProcessID == 0) || (_ModuleHandle == IntPtr.Zero) || (procAddr == IntPtr.Zero)) return false;
            return RunDLLFuncAsThread(_ProcessID, procAddr, ref exStr, maxBuffSize);
        }

        // Run Procedure/Function/Method in Initializated Module of Process as Thread with struct*/array* as parameter
        public bool RunThread(IntPtr procAddr, ref byte[] data)
        {
            if ((_ProcessID == 0) || (_ModuleHandle == IntPtr.Zero) || (procAddr == IntPtr.Zero)) return false;
            return RunDLLFuncAsThread(_ProcessID, procAddr, ref data);
        }

        // DeInitialize Object
        public void DeInit()
        {
            if ((_KillOnDeInit) && (_ProcessID != 0))
            {
                System.Diagnostics.Process[] ProcList = System.Diagnostics.Process.GetProcesses();
                if ((ProcList != null) && (ProcList.Length != 0))
                    foreach (System.Diagnostics.Process proc in ProcList)
                        if (proc.Id == _ProcessID)
                        {
                            proc.Kill();
                            //proc.WaitForExit();
                            break;
                        };
            };

            _ModuleHandle = IntPtr.Zero;
            _ModuleName = String.Empty;
            _ProcessName = String.Empty;
            _ProcessID = 0;
            _RunIfNot = false;
            _KillOnDeInit = false;
        }

        private static string GetCurrentDir()
        {
            string fname = System.Reflection.Assembly.GetExecutingAssembly().GetName().CodeBase.ToString();
            fname = fname.Replace("file:///", "");
            fname = fname.Replace("/", @"\");
            fname = fname.Substring(0, fname.LastIndexOf(@"\") + 1);
            return fname;
        }
    }
}

/*
 #
 # Calling DLL from Python
 #
 
 from ctypes import *
 
 print "C# lib:"
 csdll = cdll.LoadLibrary("UnmanagedExports.dll") # cdecl dll
 print "  ", csdll._name, " - ok"
 csdll.Test()
 print "   Test() called"
 print "   GetLibName() = ", c_char_p(csdll.GetLibName())
 cal_was = c_char_p(csdll.GetCallerName())
 csdll.SetCallerName(c_char_p(b"Passed by Python"))
 cal_set = c_char_p(csdll.GetCallerName())
 print "   Caller set from", cal_was, "to" , cal_set
 
 */

/*
 //
 // Calling DLL from C++
 //
 
 char* dllNameA    =  "csharplib.dll"; // ANSI string
 HINSTANCE pLib = LoadLibraryA(dllNameA);  
 typedef void (__cdecl * TestFunc)();	
 TestFunc Test = (TestFunc) GetProcAddress(pLib, "Test");	
 Test();

 typedef char* (__cdecl * GetLibNameFunc)();
 GetLibNameFunc GetLibName = (GetLibNameFunc) GetProcAddress(pLib, "GetLibName");
 char* nm = GetLibName();

 typedef char* (__cdecl * GetCallerNameFunc)();
 typedef void* (__cdecl * SetCallerNameFunc)(char*);
 GetCallerNameFunc GetCallerName = (GetCallerNameFunc) GetProcAddress(pLib, "GetCallerName");
 SetCallerNameFunc SetCallerName = (SetCallerNameFunc) GetProcAddress(pLib, "SetCallerName");

 char* caller = GetCallerName();
 SetCallerName("HelloWorld");
 caller = GetCallerName();
 
 */

/*
 //
 // Calling DLL from Delphi
 //
 
 procedure Test(); cdecl; external 'UnmanagedExports.dll'; 
 function GetLibName(): PChar; cdecl; external 'UnmanagedExports.dll';
 procedure SetCallerName(str: PChar); cdecl; external 'UnmanagedExports.dll';
 function GetCallerName(): PChar; cdecl; external 'UnmanagedExports.dll';
 
 var
   str: PChar;
 begin
   Test();
   str := GetLibName();
   str := PChar('Passed From Delphi');
   SetCallerName(str);
   str := GetCallerName();
 end;
 
 */
