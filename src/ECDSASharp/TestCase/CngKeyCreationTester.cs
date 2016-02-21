using System;
using System.Security.Cryptography;
using log4net;

namespace ECDSASharp.TestCase
{
    internal static class CngKeyCreationTester
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(CngKeyCreationTester));

        internal static void DoTest()
        {
            //DoTestECDsa();
            DoTestRSA();
            ECDSAKeyTest();
        }

        private static void ECDSAKeyTest()
        {
            //待签名数据
            byte[] data = System.Text.Encoding.UTF8.GetBytes("Text");

            //创建椭圆密钥对
            CngKeyCreationParameters keyCreationParameters = new CngKeyCreationParameters();
            keyCreationParameters.ExportPolicy = CngExportPolicies.AllowPlaintextExport;
            keyCreationParameters.KeyUsage = CngKeyUsages.Signing;
            CngKey key = CngKey.Create(CngAlgorithm.ECDsaP256, null, keyCreationParameters);
            byte[] privateKeyBlob = key.Export(CngKeyBlobFormat.EccPrivateBlob);
            byte[] publicKeyBlob = key.Export(CngKeyBlobFormat.EccPublicBlob);

            CngKey privateKey = CngKey.Import(privateKeyBlob, CngKeyBlobFormat.EccPrivateBlob);
            CngKey publicKey = CngKey.Import(publicKeyBlob, CngKeyBlobFormat.EccPublicBlob);

            //使用私钥签名
            ECDsaCng dsa1 = new ECDsaCng(privateKey);
            dsa1.HashAlgorithm = CngAlgorithm.Sha256;
            byte[] signature = dsa1.SignData(data);

            //使用公钥验签
            ECDsaCng dsa2 = new ECDsaCng(publicKey);
            dsa2.HashAlgorithm = CngAlgorithm.Sha256;
            bool bVerified = dsa2.VerifyData(data, signature);

            if (bVerified)
                Console.WriteLine("Verified");
            else
                Console.WriteLine("Not verified");

        }

        internal static void DoTestECDsa()
        {
            ECDsaCng dsa = new ECDsaCng(256);
            dsa.HashAlgorithm = CngAlgorithm.Sha256;

            byte[] data = System.Text.Encoding.UTF8.GetBytes("Text");
            byte[] signature = dsa.SignData(data);
            string strX = Convert.ToBase64String(signature);




            if (dsa.VerifyData(data, signature))
                Console.WriteLine("Verified");
            else
                Console.WriteLine("Not verified");


        }

        internal static void DoTestRSA()
        {
            string oid = CryptoConfig.MapNameToOID("SHA256");
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(3072))
            {

                byte[] data = System.Text.Encoding.UTF8.GetBytes("Text");
                byte[] signature = rsa.SignData(data, oid);
                string strX = Convert.ToBase64String(signature);

                if (rsa.VerifyData(data, oid, signature))
                    Console.WriteLine("Verified");
                else
                    Console.WriteLine("Not verified");
            }
        }



    }
}
