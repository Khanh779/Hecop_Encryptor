using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Hecop_Encryptor.Encryptor
{
    public class DsaEncryption
    {
        private System.Security.Cryptography.DSA dsaProvider;


        public DsaEncryption()
        {
            // Tạo DSA provider, có thể dùng ECDsaCng nếu muốn sử dụng Elliptic Curve DSA
            dsaProvider = DSA.Create(); // Tự động chọn nhà cung cấp dựa trên hệ điều hành
        }

        // Tạo khoá công khai và khoá riêng tư
        public DSAParameters ExportKeys()
        {
            return dsaProvider.ExportParameters(true); // true để xuất cả khoá riêng tư
        }

        // Nhập khoá công khai và khoá riêng tư
        public void ImportKeys(DSAParameters keys)
        {
            dsaProvider.ImportParameters(keys);
        }

        // Ký dữ liệu
        public byte[] SignData(byte[] data)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(data);
                return dsaProvider.CreateSignature(hash);
            }
        }

        // Xác thực chữ ký
        public bool VerifyData(byte[] data, byte[] signature)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(data);
                return dsaProvider.VerifySignature(hash, signature);
            }
        }

        //// Lấy cặp khoá công khai và riêng
        //public string GetPublicKey()
        //{
        //    return dsaProvider.ToXmlString(false); // Chỉ public key
        //}

        //public string GetPrivateKey()
        //{
        //    return dsaProvider.ToXmlString(true); // Public và private key
        //}

        // Lấy cặp khoá công khai và riêng dưới dạng chuỗi Base64 (thay vì XML)
        public string GetPublicKey()
        {
            var publicKey = dsaProvider.ExportParameters(false);
            return Convert.ToBase64String(publicKey.Seed); // Chỉ xuất public key, có thể tuỳ chỉnh xuất theo cách khác
        }

        public string GetPrivateKey()
        {
            var privateKey = dsaProvider.ExportParameters(true);
            return Convert.ToBase64String(privateKey.Seed); // Xuất private key (thông qua Base64)
        }
    }
}
