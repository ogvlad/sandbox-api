using Newtonsoft.Json;

namespace SandboxAPI.Encryption
{
    public class DeliveringKeyModel
    {
        public string Mode { get; set; }
        public string EncryptedMessage { get; set; }

    }
}
