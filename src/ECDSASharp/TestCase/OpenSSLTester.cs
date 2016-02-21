using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using ECDSASharp.Utility;
using log4net;

namespace ECDSASharp.TestCase
{
    internal static class OpenSSLTester
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(OpenSSLTester));

        private const string ECCOID  = "1.2.840.10045.2.1";     //ECC
        private const string P256OID = "1.2.840.10045.3.1.7";   //ECDSA_P256 (= NIST P-256, P-256, prime256v1, secp256r1)

        private const string P384OID = "1.3.132.0.34";
        private const string P521OID = "1.3.132.0.35";

        internal static void DoTest()
        {
            //待签名数据
            byte[] data = Encoding.UTF8.GetBytes("Hello World.");

            CngKey privateKey = GetPrivateKey(@"..\..\TestData\prime256v1.key");
            CngKey pubKey = GetPublicKey(@"..\..\TestData\prime256v1.pub");

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

        private static CngKey GetPrivateKey(string v)
        {
            string str = File.ReadAllText(v, Encoding.ASCII);
            str = str.Replace("-----BEGIN EC PRIVATE KEY-----", "");
            str = str.Replace("-----END EC PRIVATE KEY-----", "");
            byte[] bs2 = System.Convert.FromBase64String(str);

            ASN1Element asn = new ASN1Element(bs2, 0);
            ASN1Element asne = asn.Childs[1] as ASN1Element;
            ASN1Element asne0 = asn.Childs[2] as ASN1Element;
            ASN1Element asne1 = ((ASN1Element)asn.Childs[2]).Childs[0] as ASN1Element;
            ASN1Element asne2 = ((ASN1Element)asn.Childs[3]).Childs[0] as ASN1Element;

            string str111 = DER2OID(asne0.Value);

            bool bSucc = StringComparer.Ordinal.Equals(str111, P256OID);

            byte[] privateKeyBlob = new byte[104];
            byte[] magic = new byte[8] { 0x45, 0x43, 0x53, 0x32, 0x20, 0x00, 0x00, 0x00 };
            Buffer.BlockCopy(magic, 0, privateKeyBlob, 0, 8);

            byte[] b = asne.Value;
            byte[] b2 = asne2.Value;

            Buffer.BlockCopy(b2, 2, privateKeyBlob, 8, 64);
            Buffer.BlockCopy(b, 0, privateKeyBlob, 8 + 64, 32);

            CngKey privateKey = CngKey.Import(privateKeyBlob, CngKeyBlobFormat.EccPrivateBlob);

            return privateKey;
        }

        private static CngKey GetPublicKey(string v)
        {
            string str = File.ReadAllText(v, Encoding.ASCII);
            str = str.Replace("-----BEGIN PUBLIC KEY-----", "");
            str = str.Replace("-----END PUBLIC KEY-----", "");
            byte[] bs2 = System.Convert.FromBase64String(str);

            ASN1Element asn = new ASN1Element(bs2, 0);

            ASN1Element asne = asn.Childs[1] as ASN1Element;
            ASN1Element asne1 = ((ASN1Element)asn.Childs[0]).Childs[0] as ASN1Element;
            ASN1Element asne2 = ((ASN1Element)asn.Childs[0]).Childs[1] as ASN1Element;

            string str111 = DER2OID(asne1.Self);
            string str112 = DER2OID(asne2.Self);

            bool bSucc = StringComparer.Ordinal.Equals(str112, P256OID);

            byte[] publicKeyBlob = new byte[72];
            byte[] magic = new byte[8] { 0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00 };
            Buffer.BlockCopy(magic, 0, publicKeyBlob, 0, 8);

            byte[] b = asne.Value;

            Buffer.BlockCopy(b, 2, publicKeyBlob, 8, 64);

            CngKey publicKey = CngKey.Import(publicKeyBlob, CngKeyBlobFormat.EccPublicBlob);

            return publicKey;
        }

        private static string DER2OID(byte[] oid)
        {
            try
            {
                if (oid[0] != 0x06 || oid[1] >= 128 || oid[1] != oid.Length - 2)
                {
                    return null;
                }

                byte firstByte = oid[2];
                string ret = (firstByte / 40) + "." + (firstByte % 40) + ".";
                for (int i = 3; i < oid.Length; i++)
                {
                    if (oid[i] < 128)
                    {
                        ret += (int)oid[i];
                    }
                    else if (oid[i] >= 128 && oid[i + 1] < 128)
                    {
                        ret += (int)(((oid[i] & 0x7f) << 7) | oid[i + 1]);
                        i++;
                    }
                    else {
                        return null;
                    }

                    if (i != oid.Length - 1)
                    {
                        ret += ".";
                    }
                }
                return ret;
            }
            catch (Exception)
            {
                return null;
            }
        }

    }
}
