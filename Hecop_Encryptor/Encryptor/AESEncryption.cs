using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Hecop_Encryptor.Encryptor
{
    internal class AESEncryption
    {
        private string key;
        private string iv;

        public AESEncryption(string key = "defaultkey123456", string iv = "defaultiv123456")
        {
            this.key = key;
            this.iv = iv;
        }

        // Mã hóa dữ liệu
        public byte[] Encrypt(byte[] data)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = System.Text.Encoding.UTF8.GetBytes(this.key);
                aesAlg.IV = System.Text.Encoding.UTF8.GetBytes(this.iv);

                aesAlg.BlockSize = GlobalValue.AESBlockSize;
                aesAlg.KeySize = GlobalValue.AESKeySize;

                using (ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                {
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(data, 0, data.Length);
                            cs.Close();
                        }
                        return ms.ToArray();
                    }
                }
            }
        }

        // Giải mã dữ liệu
        public byte[] Decrypt(byte[] data)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = System.Text.Encoding.UTF8.GetBytes(this.key);
                aesAlg.IV = System.Text.Encoding.UTF8.GetBytes(this.iv);

                aesAlg.BlockSize = GlobalValue.AESBlockSize;
                aesAlg.KeySize = GlobalValue.AESKeySize;

                using (ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                {
                    using (MemoryStream ms = new MemoryStream(data))
                    {
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            byte[] decryptedData = new byte[data.Length];
                            int bytesRead = cs.Read(decryptedData, 0, decryptedData.Length);
                            return decryptedData.Take(bytesRead).ToArray();
                        }
                    }
                }
            }
        }
    }
}
