// SECURITY WARNING (PoC): Secret is stored in plaintext in app local storage. This is INSECURE and for demo only.
// This PoC uses ZERO ENCRYPTION. Only Windows Hello signature verification gates access.
namespace HelloSealUwp.Models
{
    public sealed class HelloBlob
    {
        public int Version { get; set; } = 1;
        public string KeyName { get; set; } = "HelloSealKey";
        public string Algorithm { get; set; } = "AUTO";
        public string PublicKeyBase64 { get; set; } = string.Empty;
        public string SecretPlaintext { get; set; } = string.Empty;
    }
}
