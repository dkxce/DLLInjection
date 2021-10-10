using System;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Net;
using System.Threading;
using System.Runtime.InteropServices;
using System.ServiceProcess;

namespace injproc
{
    class Program
    {
        static bool run_if_not = true;
        static void Main(string[] args)
        {
            // 0 argument - DLL File
            // 1 argument - Exe to Inject
            Inject(args, run_if_not);
        }

        private static void Inject(string[] args, bool run_exe)
        {
            string dllName = args[0];
            string exeName = args[1];
            string dllLnme = "";

            try
            {
                IntPtr pDLL = InjLibExports.LoadLibrary(dllName);
                if (pDLL != IntPtr.Zero)
                {
                    IntPtr pGetLibName = InjLibExports.GetProcAddress(pDLL, "GetLibName");
                    InjLibExports.GetLibNameFunc callF = (InjLibExports.GetLibNameFunc)Marshal.GetDelegateForFunctionPointer(pGetLibName, typeof(InjLibExports.GetLibNameFunc));
                    dllLnme = callF();
                };
                InjLibExports.FreeLibrary(pDLL);
                Console.WriteLine("  Using: " + dllLnme);
            }
            catch { };

            Inject(dllName, exeName, run_exe);
        }

        private static void Inject(string dll, string exe, bool run_exe)
        {
            injlib.InjectDLL indll = new injlib.InjectDLL();
            if (!run_if_not)
                indll.Init(exe, dll);
            else
                indll.InitRun(exe, "", dll);

            if (indll.ModuleHandle != IntPtr.Zero)
            {
                IntPtr[] procAddrs = indll.GetProcAddr(new string[] { "Test", "ShowMessage" });                
                indll.RunThread(procAddrs[0]);
                string extStr = "Call ShowMessage function from " + dll + " in " + exe;
                indll.RunThread(procAddrs[1], ref extStr);
            };
            indll.KillOnDeInit = false;
            indll.DeInit();
        }
    }
   

    internal static class InjLibExports
    {
        // Test DLL in C# Application //

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate string GetLibNameFunc();
        
        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [DllImport("kernel32.dll")]
        public static extern bool FreeLibrary(IntPtr hModule);
    }
}
