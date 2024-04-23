using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hecop_Encryptor.Encryptor
{
    public class XOREncryptDecrypt
    {
        public static string XorEncryptDecrypt(string input, string key)
        {
            var result = "";
            for (int i = 0; i < input.Length; i++)
            {
                result += (char)(input[i] ^ key[i % key.Length]);
            }
            return result;
        }
    }
}
