using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Hecop_Encryptor.Encryptor
{
    public class DESEncryption
    {
        private string key;
        private string iv;

        public DESEncryption(string key = "defaultk1", string iv = "defaultiv")
        {
            this.key = key;
            this.iv = iv;
        }

        // Mã hóa dữ liệu
        public byte[] Encrypt(byte[] data)
        {
            using (DESCryptoServiceProvider desAlg = new DESCryptoServiceProvider())
            {
                desAlg.Key = System.Text.Encoding.UTF8.GetBytes(this.key);
                desAlg.IV = System.Text.Encoding.UTF8.GetBytes(this.iv);

                desAlg.BlockSize = GlobalValue.DESBlockSize;
                desAlg.KeySize = GlobalValue.DESKeySize;

                using (ICryptoTransform encryptor = desAlg.CreateEncryptor(desAlg.Key, desAlg.IV))
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
            using (DESCryptoServiceProvider desAlg = new DESCryptoServiceProvider())
            {
                desAlg.Key = System.Text.Encoding.UTF8.GetBytes(this.key);
                desAlg.IV = System.Text.Encoding.UTF8.GetBytes(this.iv);

                desAlg.BlockSize = GlobalValue.DESBlockSize;
                desAlg.KeySize = GlobalValue.DESKeySize;

                using (ICryptoTransform decryptor = desAlg.CreateDecryptor(desAlg.Key, desAlg.IV))
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
