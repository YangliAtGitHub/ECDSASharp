using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using ECDSASharp.Utility;

namespace ECDSASharp
{
    //本类仅用于P-256密钥。
    internal static class OpenSSLKeyECC
    {
        private const string ECCOID = "1.2.840.10045.2.1";
        private const string P256OID = "1.2.840.10045.3.1.7";   //ECDSA_P256 (= NIST P-256, P-256, prime256v1, secp256r1)
        private const string P384OID = "1.3.132.0.34";          //没用，本类仅实现了P-256(prime256v1)
        private const string P521OID = "1.3.132.0.35";          //没用，本类仅实现了P-256(prime256v1)

        private readonly static byte[] bsPublicKey = new byte[]
        {
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
            0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
            0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04
        };

        private readonly static byte[] bsPrivateKey = new byte[]
        {
            0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
            0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
            0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04
        };

        internal static byte[] ConvertPublicBlob(byte[] publicKeyBlob)
        {

            byte[] bs = new byte[bsPublicKey.Length + 64];
            Buffer.BlockCopy(bsPublicKey, 0, bs, 0, bsPublicKey.Length);
            Buffer.BlockCopy(publicKeyBlob, 8, bs, bsPublicKey.Length, 64);

            StringBuilder sb = new StringBuilder("-----BEGIN PUBLIC KEY-----");
            string strTemp = Convert.ToBase64String(bs, Base64FormattingOptions.InsertLineBreaks);
            sb.AppendLine(strTemp);
            sb.AppendLine("-----END PUBLIC KEY-----");

            byte[] bs2 = Encoding.ASCII.GetBytes(sb.ToString());
            return bs2;
        }

        internal static byte[] ConvertPrivateBlob(byte[] privateKeyBlob)
        {

            byte[] bs = new byte[bsPrivateKey.Length + 64];
            Buffer.BlockCopy(bsPrivateKey, 0, bs, 0, bsPrivateKey.Length);
            Buffer.BlockCopy(privateKeyBlob, 8, bs, 7, 32);
            Buffer.BlockCopy(privateKeyBlob, 72, bs, bsPrivateKey.Length-1, 64);

            StringBuilder sb = new StringBuilder("-----BEGIN EC PRIVATE KEY-----");
            string strTemp = Convert.ToBase64String(bs, Base64FormattingOptions.InsertLineBreaks);
            sb.AppendLine(strTemp);
            sb.AppendLine("-----END EC PRIVATE KEY-----");

            byte[] bs2 = Encoding.ASCII.GetBytes(sb.ToString());
            return bs2;
        }

        public static CngKey GetPrivateKey(string v)
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

        public static CngKey GetPublicKey(string v)
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
