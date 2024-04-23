using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hecop_Encryptor.Encryptor
{
    public class SubstitutionHelper
    {
        public static byte[] SubstituteText(string input, string substitution, string replacement)
        {
            // Tìm vị trí của chuỗi cần thay thế trong chuỗi đầu vào
            int startIndex = input.IndexOf(substitution);

            // Nếu không tìm thấy chuỗi cần thay thế, trả về chuỗi gốc
            if (startIndex == -1)
            {
                return Encoding.UTF8.GetBytes( input);
            }

            // Thực hiện phép thay thế
            string result = input.Substring(0, startIndex) + replacement + input.Substring(startIndex + substitution.Length);

            return Encoding.UTF8.GetBytes(result);
        }
    }
}
