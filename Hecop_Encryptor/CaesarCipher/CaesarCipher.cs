using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hecop_Encryptor.CaesarCipher
{
    public class CaesarCipher
    {
        private static int shift=2;

        public static byte[] Encrypt(string plaintext)
        {
            byte[] data = Encoding.UTF8.GetBytes(plaintext);
            byte[] encryptedData = new byte[data.Length];

            for (int i = 0; i < data.Length; i++)
            {
                byte c = data[i];

                // Check if the character is a letter
                if (IsLetter(c))
                {
                    byte baseChar = IsUppercase(c) ? (byte)'A' : (byte)'a';
                    encryptedData[i] = (byte)(((c - baseChar + shift) % 26) + baseChar);
                }
                else
                {
                    encryptedData[i] = c; // Keep non-letter characters unchanged
                }
            }

            return encryptedData;
        }

        public static string Decrypt(byte[] ciphertext)
        {
            byte[] decryptedData = new byte[ciphertext.Length];
            shift = 26 - shift; // To perform the reverse shift

            for (int i = 0; i < ciphertext.Length; i++)
            {
                byte c = ciphertext[i];

                // Check if the character is a letter
                if (IsLetter(c))
                {
                    byte baseChar = IsUppercase(c) ? (byte)'A' : (byte)'a';
                    decryptedData[i] = (byte)(((c - baseChar + shift) % 26) + baseChar);
                }
                else
                {
                    decryptedData[i] = c; // Keep non-letter characters unchanged
                }
            }

            return Encoding.UTF8.GetString(decryptedData);
        }

        private static bool IsLetter(byte c)
        {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        }

        private static bool IsUppercase(byte c)
        {
            return c >= 'A' && c <= 'Z';
        }
    }
}
