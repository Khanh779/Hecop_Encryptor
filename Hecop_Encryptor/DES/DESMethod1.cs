using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Hecop_Encryptor.DES
{
    public partial class DESMethod1
    {
        public static void Encrypt(string inputPath, string outputPath, string key)
        {
            using (FileStream fsInput = new FileStream(inputPath, FileMode.Open))
            using (FileStream fsOutput = new FileStream(outputPath, FileMode.Create))
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                byte[] ivBytes = Encoding.UTF8.GetBytes(key);

                des.BlockSize = GlobalValue.DESBlockSize;
                des.KeySize = GlobalValue.DESKeySize;

                des.Key = keyBytes;
                des.IV = ivBytes;
              
                using (CryptoStream cryptoStream = new CryptoStream(fsOutput, des.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    try
                    {
                        Application.DoEvents();
                        fsInput.CopyTo(cryptoStream);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.ToString());
                        //Debug.WriteLine(ex.ToString());
                    }
                    finally
                    {
                        cryptoStream.Close();
                        fsInput.Close();
                    }

                }
            }
        }


        public static void Decrypt(string inputPath, string outputPath, string key)
        {
            using (FileStream fsInput = new FileStream(inputPath, FileMode.Open))
            using (FileStream fsOutput = new FileStream(outputPath, FileMode.Create))
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                byte[] ivBytes = Encoding.UTF8.GetBytes(key);

                des.BlockSize = GlobalValue.DESBlockSize;
                des.KeySize = GlobalValue.DESKeySize;

                des.Key = keyBytes;
                des.IV = ivBytes;
            
                using (CryptoStream cryptoStream = new CryptoStream(fsOutput, des.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    try
                    {
                        Application.DoEvents();
                        fsInput.CopyTo(cryptoStream);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.ToString());
                        //Debug.WriteLine(ex.ToString());
                    }
                    finally
                    {
                        cryptoStream.Close();
                        fsInput.Close();
                    }
                }
            }
        }
    }
}
