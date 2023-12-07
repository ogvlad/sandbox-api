using System.Security.Cryptography;
using System.Text;

namespace SandboxAPI.Encryption
{
    public sealed class DeliveringKeyManager
    {
        public static DeliveringKeyModel GetEncryptedKey(Request request)
        {
            string textToEncrypt = "A quick brown fox jumps over the lazy dog";

            byte[] publicKeyBytes = Convert.FromBase64String(request.publicKeyBase64);

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

                byte[] encryptedBytes = rsa.Encrypt(Encoding.UTF8.GetBytes(textToEncrypt), true);
                string encryptedText = Convert.ToBase64String(encryptedBytes);
                return new DeliveringKeyModel
                {
                    EncryptedMessage = encryptedText,
                };
            }
        }
    }
}
