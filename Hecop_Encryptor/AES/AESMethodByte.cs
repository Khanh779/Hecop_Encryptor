using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Hecop_Encryptor.AES
{
    internal class AESMethodByte
    {
        static int saltBytes
        {
            get
            {
                return Convert.ToInt32(GenerateRandomSalt());
            }
        }

        public static byte[] GenerateRandomSalt()
        {
            byte[] data = new byte[32];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                for (int i = 0; i < 10; i++)
                {
                    rng.GetBytes(data);
                }
            }

            return data;
        }

        public static byte[] EncryptBytesAES(byte[] data, string password)
        {

            byte[] encryptedData;

            using (Aes aes = Aes.Create())
            {
                byte[] key = new Rfc2898DeriveBytes(password, saltBytes).GetBytes(32);
                aes.Key = key;
                aes.IV = new byte[16];
                aes.KeySize = 256; aes.BlockSize = 128;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                    }

                    encryptedData = ms.ToArray();
                }
            }

            return encryptedData;
        }

        public static byte[] DecryptBytesAES(byte[] encryptedData, string password)
        {
            byte[] decryptedText;

            using (Aes aes = Aes.Create())
            {
                byte[] key = new Rfc2898DeriveBytes(password, saltBytes).GetBytes(32);
                aes.Key = key;
                aes.IV = new byte[16];
                aes.KeySize = 256; aes.BlockSize = 128;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream(encryptedData))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader reader = new StreamReader(cs))
                        {
                            decryptedText = Encoding.UTF8.GetBytes(reader.ReadToEnd());
                        }
                    }
                }
            }

            return decryptedText;
        }

        public byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;

            // Generate a random salt
            byte[] saltBytes = GenerateRandomSalt();

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }

        public byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes, byte[] saltBytes)
        {
            byte[] decryptedBytes = null;

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }

        // Function to generate a random salt
        //private byte[] GenerateRandomSalt()
        //{
        //    byte[] salt = new byte[8]; // You can change the size of the salt if needed
        //    using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
        //    {
        //        rngCsp.GetBytes(salt);
        //    }
        //    return salt;
        //}
    }
}
