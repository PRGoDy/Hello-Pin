// SECURITY WARNING (PoC): Secret is stored in plaintext in app local storage. This is INSECURE and for demo only.
// This PoC uses ZERO ENCRYPTION. Only Windows Hello signature verification gates access.
using System;
using System.Threading.Tasks;
using HelloSealUwp.Models;
using Windows.Data.Json;
using Windows.Storage;

namespace HelloSealUwp.Services
{
    public sealed class HelloStore
    {
        private const string FileName = "helloseal.json";

        public async Task SaveAsync(HelloBlob blob)
        {
            if (blob == null)
            {
                throw new ArgumentNullException(nameof(blob));
            }

            var folder = ApplicationData.Current.LocalFolder;
            var file = await folder.CreateFileAsync(FileName, CreationCollisionOption.ReplaceExisting);
            var json = new JsonObject
            {
                ["Version"] = JsonValue.CreateNumberValue(blob.Version),
                ["KeyName"] = JsonValue.CreateStringValue(blob.KeyName ?? string.Empty),
                ["Algorithm"] = JsonValue.CreateStringValue(blob.Algorithm ?? "AUTO"),
                ["PublicKeyBase64"] = JsonValue.CreateStringValue(blob.PublicKeyBase64 ?? string.Empty),
                ["SecretPlaintext"] = JsonValue.CreateStringValue(blob.SecretPlaintext ?? string.Empty)
            };

            await FileIO.WriteTextAsync(file, json.Stringify());
        }

        public async Task<HelloBlob> LoadAsync()
        {
            try
            {
                var folder = ApplicationData.Current.LocalFolder;
                var file = await folder.GetFileAsync(FileName);
                var text = await FileIO.ReadTextAsync(file);
                if (string.IsNullOrWhiteSpace(text))
                {
                    return null;
                }

                var json = JsonObject.Parse(text);
                var blob = new HelloBlob
                {
                    Version = (int)(json.ContainsKey("Version") ? json["Version"].GetNumber() : 1),
                    KeyName = json.ContainsKey("KeyName") ? json["KeyName"].GetString() : string.Empty,
                    Algorithm = json.ContainsKey("Algorithm") ? json["Algorithm"].GetString() : "AUTO",
                    PublicKeyBase64 = json.ContainsKey("PublicKeyBase64") ? json["PublicKeyBase64"].GetString() : string.Empty,
                    SecretPlaintext = json.ContainsKey("SecretPlaintext") ? json["SecretPlaintext"].GetString() : string.Empty
                };

                if (string.IsNullOrWhiteSpace(blob.KeyName) || string.IsNullOrWhiteSpace(blob.PublicKeyBase64))
                {
                    throw new InvalidOperationException("Stored blob is missing required fields.");
                }

                return blob;
            }
            catch (System.IO.FileNotFoundException)
            {
                return null;
            }
        }
    }
}
