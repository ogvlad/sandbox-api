using System.Security.Cryptography;
using System.Text;

namespace SandboxAPI.Encryption
{
    public sealed class DeliveringKeyManager
    {
        private const int RsaKeySize = 2048;
        private const int AesKeyLength = 32;
        private const int AesIvLength = 16;

        public static DeliveringKeyModel GetEncryptedKey(Request request)
        {
            string textToEncrypt = "A quick brown fox jumps over the lazy dog";

            try
            {
                // Convert the public key from Base64 to byte array
                byte[] publicKeyBytes = Convert.FromBase64String(request.publicKeyBase64);

                // Initialize RSACryptoServiceProvider with the public key
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    // Import the public key
                    rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

                    byte[] encryptedBytes = rsa.Encrypt(Encoding.UTF8.GetBytes(textToEncrypt), RSAEncryptionPadding.OaepSHA256);
                    string encryptedText = Convert.ToBase64String(encryptedBytes);
                    return new DeliveringKeyModel
                    {
                        EncryptedMessage = encryptedText,
                    };
                }
            }
            catch (Exception ex)
            {
                return new DeliveringKeyModel();
            }
        }
    }
}
