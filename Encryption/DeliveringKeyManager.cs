using System;
using System.Security.Cryptography;
using System.Text;

namespace SandboxAPI.Encryption
{
    public sealed class DeliveringKeyManager
    {
        const int RsaKeySize = 1024;
        const string TextToEncrypt = "A quick brown fox jumps over the lazy dog";

        public static DeliveringKeyModel GetEncryptedKey_Binary(Request request)
        {
            var publicKey = Convert.FromBase64String(request.publicKeyBase64);
            var data = Encoding.UTF8.GetBytes(TextToEncrypt);

            using RSACryptoServiceProvider provider = new RSACryptoServiceProvider(RsaKeySize);
            provider.ImportSubjectPublicKeyInfo(publicKey, out _);

            byte[] encryptedBytes = provider.Encrypt(data, true);
            string encryptedText = Convert.ToBase64String(encryptedBytes);
            return new DeliveringKeyModel
            {
                EncryptedMessage = encryptedText,
                Mode = $"Binary Key - {DateTime.Now.ToLongTimeString()}"
            };
        }

        public static DeliveringKeyModel GetEncryptedKey_XML(Request request)
        {
            var data = Encoding.UTF8.GetBytes(TextToEncrypt);

            var encryptKey = string.Concat("<RSAKeyValue><Modulus>", request.publicKeyBase64,
                "</Modulus><Exponent>Aw==</Exponent></RSAKeyValue>");

            using RSACryptoServiceProvider provider = new RSACryptoServiceProvider(RsaKeySize);
            provider.FromXmlString(encryptKey);
            var encryptedBytes = provider.Encrypt(data, true);
            string encryptedText = Convert.ToBase64String(encryptedBytes);

            return new DeliveringKeyModel
            {
                EncryptedMessage = encryptedText,
                Mode = $"XML Key - {DateTime.Now.ToLongTimeString()}"
            };
        }
    }
}
