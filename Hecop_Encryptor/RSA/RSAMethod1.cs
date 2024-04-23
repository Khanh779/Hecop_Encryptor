using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Hecop_Encryptor.RSA
{
    public partial class RSAMethod1
    {
        RSACryptoServiceProvider rsa;

        public RSAMethod1() { 

            rsa= new RSACryptoServiceProvider();

        }

        public byte[] Encrypt(string plaintext)
        {
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] encryptedBytes = rsa.Encrypt(plaintextBytes, true);

            return encryptedBytes;
        }

        public string Decrypt(string encryptedText)
        {
            byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
            byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, true);
            string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
            return decryptedText;
        }


        public byte[] ExportPublicKey()
        {
            RSAParameters publicKeyParams = rsa.ExportParameters(false);
            return publicKeyParams.Modulus;
        }

        public void ImportPublicKey(byte[] publicKeyBlob)
        {
            RSAParameters publicKeyParams = new RSAParameters();
            publicKeyParams.Modulus = publicKeyBlob;
            rsa.ImportParameters(publicKeyParams);
        }

        public byte[] ExportPrivateKey()
        {
            RSAParameters privateKeyParams = rsa.ExportParameters(true);
            return privateKeyParams.D;
        }

        public void ImportPrivateKey(byte[] privateKeyBlob)
        {
            RSAParameters privateKeyParams = new RSAParameters();
            privateKeyParams.D = privateKeyBlob;
            rsa.ImportParameters(privateKeyParams);

        }
    }
}
