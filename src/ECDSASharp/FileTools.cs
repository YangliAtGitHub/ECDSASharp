using System.IO;

namespace ECDSASharp.Utility
{
    internal class FileTools
    {
        public static void WriteToFile( string filePath, byte[] bytes)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
            {
                fs.Write(bytes, 0, bytes.Length);
                fs.Flush();
            }
        }
    }
}
