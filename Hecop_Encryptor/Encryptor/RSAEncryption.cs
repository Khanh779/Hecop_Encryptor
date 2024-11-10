using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Hecop_Encryptor.Encryptor
{
    internal class RSAEncryption
    {
        //public static byte[] Encrypt(byte[] input, string publicKey)
        //{
        //    //RSACryptoServiceProvider a = new RSACryptoServiceProvider();

        //    using (RSACng rsa = new RSACng())
        //    {
        //        rsa.FromXmlString(publicKey);
        //        return rsa.Encrypt(input, RSAEncryptionPadding.OaepSHA256);
        //    }
        //}

        //public static byte[] Decrypt(byte[] input, string privateKey)
        //{
        //    using (RSACng rsa = new RSACng())
        //    {

        //        rsa.FromXmlString(privateKey);
        //        return rsa.Decrypt(input, RSAEncryptionPadding.OaepSHA256);
        //    }
        //}

        private RSA rsa;

        public RSAEncryption()
        {
            rsa = RSA.Create();
        }

        // Mã hóa dữ liệu
        public byte[] Encrypt(byte[] data)
        {
            return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
        }

        // Giải mã dữ liệu
        public byte[] Decrypt(byte[] data)
        {
            return rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
        }

        // Đặt cặp khoá (private và public)
        public void SetKeys(string publicKey, string privateKey)
        {
            rsa.FromXmlString(privateKey);
            rsa.FromXmlString(publicKey);
        }
    }
}
