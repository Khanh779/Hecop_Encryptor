#define DEBUG
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Hecop_Encryptor.CryptorStuff
{
    internal static class CryptoStuff
    {
        private static void MakeKeyAndIV(string password, byte[] salt, int key_size_bits, int block_size_bits, out byte[] key, out byte[] iv)
        {
            Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, 1000);
            key = rfc2898DeriveBytes.GetBytes(key_size_bits / 8);
            iv = rfc2898DeriveBytes.GetBytes(block_size_bits / 8);
        }

        public static void EncryptFile(string password, string inFile, string outFile)
        {
            CryptFile(password, inFile, outFile, encrypt: true);
        }

        public static void DecryptFile(string password, string inFile, string outFile)
        {
            CryptFile(password, inFile, outFile, encrypt: false);
        }

        public static void CryptFile(string password, string in_file, string out_file, bool encrypt)
        {
            using (FileStream in_stream = new FileStream(in_file, FileMode.Open, FileAccess.Read))
            using (FileStream out_stream = new FileStream(out_file, FileMode.Create, FileAccess.Write))
                CryptStream(password, in_stream, out_stream, encrypt);
        }

        public static void CryptStream(string password, Stream in_stream, Stream out_stream, bool encrypt)
        {
            AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider();
            int num = 0;
            for (int num2 = 1024; num2 > 1; num2--)
            {
                if (aesCryptoServiceProvider.ValidKeySize(num2))
                {
                    num = num2;
                    break;
                }
            }
            Debug.Assert(num > 0);
            Console.WriteLine("Key size: " + num);
            int blockSize = aesCryptoServiceProvider.BlockSize;
            byte[] key = null;
            byte[] iv = null;
            byte[] salt = new byte[14]
            {
                0, 0, 1, 2, 3, 4, 5, 6, 241, 240,
                238, 33, 34, 69
            };
            MakeKeyAndIV(password, salt, num, blockSize, out key, out iv);
            ICryptoTransform cryptoTransform = ((!encrypt) ? aesCryptoServiceProvider.CreateDecryptor(key, iv) : aesCryptoServiceProvider.CreateEncryptor(key, iv));
            try
            {
                CryptoStream cryptoStream = new CryptoStream(out_stream, cryptoTransform, CryptoStreamMode.Write);
                byte[] buffer = new byte[1024];
                while (true)
                {
                    int num3 = in_stream.Read(buffer, 0, 1024);
                    if (num3 == 0)
                    {
                        break;
                    }
                    cryptoStream.Write(buffer, 0, num3);
                }
            }
            catch
            {
            }
            cryptoTransform.Dispose();
        }

        public static byte[] CryptBytes(string password, byte[] in_bytes, bool encrypt)
        {
            AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider();
            int num = 0;
            for (int num2 = 1024; num2 > 1; num2--)
            {
                if (aesCryptoServiceProvider.ValidKeySize(num2))
                {
                    num = num2;
                    break;
                }
            }
            Debug.Assert(num > 0);
            Console.WriteLine("Key size: " + num);
            int blockSize = aesCryptoServiceProvider.BlockSize;
            byte[] key = null;
            byte[] iv = null;
            byte[] salt = new byte[14]
            {
                0, 0, 1, 2, 3, 4, 5, 6, 241, 240,
                238, 33, 34, 69
            };
            MakeKeyAndIV(password, salt, num, blockSize, out key, out iv);
            ICryptoTransform transform = ((!encrypt) ? aesCryptoServiceProvider.CreateDecryptor(key, iv) : aesCryptoServiceProvider.CreateEncryptor(key, iv));
            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write);
            cryptoStream.Write(in_bytes, 0, in_bytes.Length);
            try
            {
                cryptoStream.FlushFinalBlock();
            }
            catch (CryptographicException)
            {
            }
            catch
            {
                throw;
            }
            return memoryStream.ToArray();
        }

        public static byte[] Encrypt(this string the_string, string password)
        {
            ASCIIEncoding aSCIIEncoding = new ASCIIEncoding();
            byte[] bytes = aSCIIEncoding.GetBytes(the_string);
            return CryptBytes(password, bytes, encrypt: true);
        }

        public static string Decrypt(this byte[] the_bytes, string password)
        {
            byte[] bytes = CryptBytes(password, the_bytes, encrypt: false);
            ASCIIEncoding aSCIIEncoding = new ASCIIEncoding();
            return aSCIIEncoding.GetString(bytes);
        }

        public static string CryptString(string password, string in_string, bool encrypt)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(in_string);
            MemoryStream in_stream = new MemoryStream(bytes);
            MemoryStream memoryStream = new MemoryStream();
            CryptStream(password, in_stream, memoryStream, encrypt: true);
            memoryStream.Seek(0L, SeekOrigin.Begin);
            StreamReader streamReader = new StreamReader(memoryStream);
            return streamReader.ReadToEnd();
        }

        public static string ToHex(this byte[] the_bytes)
        {
            return the_bytes.ToHex(add_spaces: false);
        }

        public static string ToHex(this byte[] the_bytes, bool add_spaces)
        {
            string text = "";
            string text2 = "";
            if (add_spaces)
            {
                text2 = " ";
            }
            for (int i = 0; i < the_bytes.Length; i++)
            {
                text = text + the_bytes[i].ToString("x2") + text2;
            }
            return text;
        }

        public static byte[] ToBytes(this string the_string)
        {
            List<byte> list = new List<byte>();
            the_string = the_string.Replace(" ", "");
            for (int i = 0; i < the_string.Length; i += 2)
            {
                list.Add(byte.Parse(the_string.Substring(i, 2), NumberStyles.HexNumber));
            }
            return list.ToArray();
        }
    }
}
