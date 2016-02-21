using System;
using System.Diagnostics;

namespace ECDSASharp.Utility
{
    internal class MemTools
    {
        public static float GetVirtualMemory()
        {
            PerformanceCounter vmCounter;
            vmCounter = new PerformanceCounter();
            vmCounter.CategoryName = "Process";
            vmCounter.CounterName = "Virtual Bytes";
            string str = AppDomain.CurrentDomain.FriendlyName;
            string str2 = Process.GetCurrentProcess().ProcessName;
            vmCounter.InstanceName = str2;
            vmCounter.MachineName = ".";
            return vmCounter.NextValue();
        }
    }
}
