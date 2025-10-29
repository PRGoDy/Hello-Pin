// SECURITY WARNING (PoC): Secret is stored in plaintext in app local storage. This is INSECURE and for demo only.
// This PoC uses ZERO ENCRYPTION. Only Windows Hello signature verification gates access.
using System;
using System.Threading.Tasks;
using Windows.Security.Credentials;
using Windows.Storage.Streams;

namespace HelloSealUwp.Services
{
    public sealed class HelloHello
    {
        public Task<bool> IsSupportedAsync()
        {
            return KeyCredentialManager.IsSupportedAsync().AsTask();
        }

        public async Task<(KeyCredential Key, IBuffer PublicKey)> EnrollAsync(string keyName)
        {
            if (string.IsNullOrWhiteSpace(keyName))
            {
                throw new ArgumentException("Key name must not be empty.", nameof(keyName));
            }

            var result = await KeyCredentialManager.RequestCreateAsync(keyName, KeyCredentialCreationOption.ReplaceExisting);
            switch (result.Status)
            {
                case KeyCredentialStatus.Success:
                    var credential = result.Credential;
                    return (credential, credential.RetrievePublicKey());
                case KeyCredentialStatus.UserCanceled:
                    throw new OperationCanceledException("Windows Hello enrollment canceled by user.");
                case KeyCredentialStatus.NotFound:
                    throw new InvalidOperationException("Windows Hello is not configured. Configure Windows Hello and try again.");
                default:
                    throw new InvalidOperationException($"KeyCredential creation failed: {result.Status}.");
            }
        }

        public async Task<KeyCredential> OpenAsync(string keyName)
        {
            if (string.IsNullOrWhiteSpace(keyName))
            {
                throw new ArgumentException("Key name must not be empty.", nameof(keyName));
            }

            var result = await KeyCredentialManager.OpenAsync(keyName);
            switch (result.Status)
            {
                case KeyCredentialStatus.Success:
                    return result.Credential;
                case KeyCredentialStatus.UserCanceled:
                    throw new OperationCanceledException("Windows Hello access canceled by user.");
                case KeyCredentialStatus.NotFound:
                    throw new InvalidOperationException("KeyCredential not found. Enroll before unlocking.");
                default:
                    throw new InvalidOperationException($"KeyCredential open failed: {result.Status}.");
            }
        }

        public async Task<IBuffer> SignAsync(KeyCredential key, IBuffer challenge)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (challenge == null)
            {
                throw new ArgumentNullException(nameof(challenge));
            }

            var result = await key.RequestSignAsync(challenge);
            switch (result.Status)
            {
                case KeyCredentialStatus.Success:
                    return result.Result;
                case KeyCredentialStatus.UserCanceled:
                    throw new OperationCanceledException("Windows Hello signature request canceled by user.");
                case KeyCredentialStatus.NotFound:
                    throw new InvalidOperationException("KeyCredential became invalid. Re-enroll to continue.");
                default:
                    throw new InvalidOperationException($"Signing failed: {result.Status}.");
            }
        }
    }
}
