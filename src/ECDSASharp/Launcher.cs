using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;
using ECDSASharp.TestCase;
using ECDSASharp.Utility;
using log4net;
using log4net.Config;

namespace ECDSASharp
{
    internal class Launcher
    {
        private static ILog log;
        static Launcher()
        {
            AppDomain ap = AppDomain.CurrentDomain;
            ap.AssemblyResolve += new ResolveEventHandler(PrivateBinPathSet);
            Thread.CurrentThread.Name = "MT";
            FileInfo fi = new FileInfo("Log4net.config");
            XmlConfigurator.Configure(fi);
            log = LogManager.GetLogger(typeof(Launcher));
            log.Info("日志初始化好了。");

            Stream myFile = File.Create("TestFile.txt");

            TextWriterTraceListener myListener = new TextWriterTraceListener(Console.Out);
            Trace.Listeners.Clear();
            Trace.Listeners.Add(myListener);
        }

        private static Assembly PrivateBinPathSet(object sender, ResolveEventArgs args)
        {
            string dllname = args.Name.IndexOf(',') == -1 ? args.Name.Trim() : args.Name.Remove(args.Name.IndexOf(','));
            if (dllname.StartsWith("mscorlib") || dllname.StartsWith("System.", StringComparison.OrdinalIgnoreCase)
                || dllname.EndsWith(".XmlSerializers", StringComparison.OrdinalIgnoreCase)
                || dllname.EndsWith(".resources", StringComparison.OrdinalIgnoreCase))
                return null;
            string path = "bin\\" + dllname + ".dll";
            if (!File.Exists(path))
            {
                path = "Libs\\" + dllname + ".dll";
                if (!File.Exists(path))
                {
                    path = "System\\" + dllname + ".dll";
                }
                if (!File.Exists(path))
                {
                    path = dllname + ".dll";
                }
            }
            Assembly a = Assembly.LoadFrom(path);
            return a;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void SafeDebugLog(string str)
        {
            if (log != null)
            {
                log.Debug(str);
            }
        }

        static void Main()
        {
            Stopwatch sw = new Stopwatch();
            GC.Collect();
            float memorySize = MemTools.GetVirtualMemory();
            long workSize = Environment.WorkingSet;
            sw.Start();
            try
            {
                MainImp();

                sw.Stop();
                GC.Collect();
                float memorySize2 = MemTools.GetVirtualMemory();
                long workSize2 = System.Environment.WorkingSet;
                float VirtualSpace = (memorySize2 - memorySize) / 1000 / 1000;
                long WorkSpace = (workSize2 - workSize) / 1000 / 1000;
                Console.WriteLine("测试样本消耗了VirtualSpace:{0}MB, WorkSpace:{1}MB, Time:{2}ms", VirtualSpace, WorkSpace, sw.ElapsedMilliseconds);
            }
            catch (OutOfMemoryException e)
            {
                Console.ForegroundColor = ConsoleColor.DarkMagenta;
                Console.WriteLine(e);
                Console.ResetColor();
            }
            catch (Exception e)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(e);
                Console.ResetColor();
            }
            finally
            {
                Console.WriteLine("Finised. total time={0}ms", sw.ElapsedMilliseconds);
                Console.WriteLine("Finised. Press enter key to continue.");
                Console.ReadLine();
            }
        }

        private static void MainImp()
        {
            OpenSSLTester.DoTest();
            //ClrMixTester.DoTest();
        }
    }
}
