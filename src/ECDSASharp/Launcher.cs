using System;
using System.Diagnostics;

namespace ECDSASharp
{
    internal class Launcher
    {
        static void Main()
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            try
            {
                TestCase.DoTest();
                sw.Stop();
                Console.WriteLine("Time:{0}ms", sw.ElapsedMilliseconds);
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
    }
}
