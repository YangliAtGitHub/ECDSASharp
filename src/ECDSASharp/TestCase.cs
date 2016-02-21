using System;
using System.Security.Cryptography;
using System.Text;
using ECDSASharp.Utility;

namespace ECDSASharp
{
    internal static class TestCase
    {
        internal static void DoTest()
        {
            //使用Windows CNG完成椭圆密码的生成，签名和验证签名
            CngTest();

            //使用由OpenSSL生成的椭圆密钥进行数字签名和验签
            ReadOpenSSLKeyTest();

            //读取OpenSSL产生的密钥，并保存成OpenSSL密钥
            ReadKeyAndWriteKeyTest();

            //使用Windows CNG生成椭圆密钥，将其装换为OpenSSL密钥格式，再读取OpenSSL的椭圆密钥，然后用其签名和验签
            FullTest();
        }

        private static void CngTest()
        {
            //待签名数据
            byte[] data = Encoding.UTF8.GetBytes("Hello World.");

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

        private static void ReadOpenSSLKeyTest()
        {
            //待签名数据
            byte[] data = Encoding.UTF8.GetBytes("Hello World.");

            //读取OpenSSL产生的椭圆私钥和公钥
            CngKey privateKey = OpenSSLKeyECC.GetPrivateKey(@"..\..\TestData\prime256v1.key");
            CngKey pubKey = OpenSSLKeyECC.GetPublicKey(@"..\..\TestData\prime256v1.pub");

            //使用私钥签名
            ECDsaCng dsa1 = new ECDsaCng(privateKey);
            dsa1.HashAlgorithm = CngAlgorithm.Sha256;
            byte[] signature = dsa1.SignData(data);

            //使用公钥验签
            ECDsaCng dsa2 = new ECDsaCng(pubKey);
            dsa2.HashAlgorithm = CngAlgorithm.Sha256;
            bool bVerified = dsa2.VerifyData(data, signature);

            if (bVerified)
                Console.WriteLine("Verified");
            else
                Console.WriteLine("Not verified");
        }

        private static void ReadKeyAndWriteKeyTest()
        {
            //读取OpenSSL产生的椭圆私钥，Import产生的CngKey私钥，不允许Export。所以这里直接获取byte[]
            byte[] privateKeyBlob = OpenSSLKeyECC.GetPrivateKeyBytes(@"..\..\TestData\prime256v1.key");

            //读取OpenSSL产生的椭圆私钥
            CngKey pubKey = OpenSSLKeyECC.GetPublicKey(@"..\..\TestData\prime256v1.pub");
            byte[] publicKeyBlob = pubKey.Export(CngKeyBlobFormat.EccPublicBlob);

            //将密钥转换保存为OpenSSL ECC密钥格式
            byte[] bytesPrivateKeyOpenSSL = OpenSSLKeyECC.ConvertPrivateBlob(privateKeyBlob);
            byte[] bytesPublicKeyOpenSSL = OpenSSLKeyECC.ConvertPublicBlob(publicKeyBlob);
            FileTools.WriteToFile(@"..\..\TestData\privateKey1.pem", bytesPrivateKeyOpenSSL);
            FileTools.WriteToFile(@"..\..\TestData\publicKey1.pem", bytesPublicKeyOpenSSL);
        }

        private static void FullTest()
        {
            //待签名数据
            byte[] data = Encoding.UTF8.GetBytes("Text");

            //创建椭圆密钥对
            CngKeyCreationParameters keyCreationParameters = new CngKeyCreationParameters();
            keyCreationParameters.ExportPolicy = CngExportPolicies.AllowPlaintextExport;
            keyCreationParameters.KeyUsage = CngKeyUsages.Signing;
            CngKey key = CngKey.Create(CngAlgorithm.ECDsaP256, null, keyCreationParameters);
            byte[] privateKeyBlob = key.Export(CngKeyBlobFormat.EccPrivateBlob);
            byte[] publicKeyBlob = key.Export(CngKeyBlobFormat.EccPublicBlob);

            //将Windows CNG的密钥转换为OpenSSL的ECC公钥和私钥，并保存到文件
            byte[] bytesPrivateKeyOpenSSL = OpenSSLKeyECC.ConvertPrivateBlob(privateKeyBlob);
            byte[] bytesPublicKeyOpenSSL = OpenSSLKeyECC.ConvertPublicBlob(publicKeyBlob);
            FileTools.WriteToFile(@"..\..\TestData\privateKey.pem", bytesPrivateKeyOpenSSL);
            FileTools.WriteToFile(@"..\..\TestData\publicKey.pem", bytesPublicKeyOpenSSL);

            //读取密钥
            CngKey privateKey = OpenSSLKeyECC.GetPrivateKey(@"..\..\TestData\privateKey.pem");
            CngKey publicKey = OpenSSLKeyECC.GetPublicKey(@"..\..\TestData\publicKey.pem");
            
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


    }
}
