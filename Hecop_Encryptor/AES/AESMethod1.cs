using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Hecop_Encryptor.AES
{
    public class AESMethod1
    {

   
    


        public static void Encrypt(string inputFile, string outputFile, string password)
        {
            byte[] salt = new byte[32];
            using (FileStream fsInput = new FileStream(inputFile, FileMode.Open))
            using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create))
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.BlockSize = GlobalValue.AESBlockSize;
                aesAlg.KeySize = GlobalValue.AESKeySize;
                aesAlg.Padding = PaddingMode.PKCS7;
                var key = new Rfc2898DeriveBytes(password, salt, 50000);
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                aesAlg.IV = key.GetBytes(aesAlg.BlockSize / 8);
                using (CryptoStream cs = new CryptoStream(fsOutput, aesAlg.CreateEncryptor(), CryptoStreamMode.Write))
                {
                   
                    try
                    {
                        Application.DoEvents();
                        fsInput.CopyTo(cs);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.ToString());
                        //Debug.WriteLine(ex.ToString());
                    }
                    finally
                    {
                        cs.Close();
                        fsInput.Close();
                    }

                }
            }
        }

        public static void Decrypt(string inputFile, string outputFile, string password)
        {
            byte[] salt =  new byte[32];
            using (FileStream fsInput = new FileStream(inputFile, FileMode.Open))
            using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create))
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.BlockSize = GlobalValue.AESBlockSize;
                aesAlg.KeySize = GlobalValue.AESKeySize;
                aesAlg.Padding = PaddingMode.PKCS7;
                var key = new Rfc2898DeriveBytes(password, salt, 50000);
                aesAlg.Key =  key.GetBytes(aesAlg.KeySize / 8);
                aesAlg.IV = key.GetBytes(aesAlg.BlockSize / 8); // Use a random IV for each file or store it with the encrypted file
                using (CryptoStream cs = new CryptoStream(fsOutput, aesAlg.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    try
                    {
                        Application.DoEvents();
                        fsInput.CopyTo(cs);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.ToString());
                        //Debug.WriteLine(ex.ToString());
                    }
                    finally
                    {
                        cs.Close();
                        fsInput.Close();
                    }
                }
            }
        }
    }
    
}
