// SECURITY WARNING (PoC): Secret is stored in plaintext in app local storage. This is INSECURE and for demo only.
// This PoC uses ZERO ENCRYPTION. Only Windows Hello signature verification gates access.
using System;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace HelloSealUwp.Services
{
    public sealed class CryptoVerify
    {
        public (bool IsValid, string Reason) VerifySignature(string publicKeyBase64, IBuffer challenge, IBuffer signature, string algorithmHint)
        {
            if (string.IsNullOrWhiteSpace(publicKeyBase64))
            {
                return (false, "Public key is missing.");
            }

            if (challenge == null || signature == null)
            {
                return (false, "Challenge or signature buffer missing.");
            }

            IBuffer publicKey;
            try
            {
                publicKey = CryptographicBuffer.DecodeFromBase64String(publicKeyBase64);
            }
            catch (Exception ex)
            {
                return (false, $"Public key decode failed: {ex.Message}");
            }

            var hashProvider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
            var hash = hashProvider.HashData(challenge);

            string lastError = string.Empty;

            if (string.Equals(algorithmHint, "ECDSA_P256", StringComparison.OrdinalIgnoreCase) || string.Equals(algorithmHint, "AUTO", StringComparison.OrdinalIgnoreCase))
            {
                if (TryVerifyEcdsa(publicKey, hash, signature, out var error))
                {
                    return (true, "ECDSA_P256");
                }

                lastError = AppendReason(lastError, error);

                if (string.Equals(algorithmHint, "ECDSA_P256", StringComparison.OrdinalIgnoreCase))
                {
                    return (false, string.IsNullOrEmpty(error) ? "ECDSA verification failed." : error);
                }
            }

            if (string.Equals(algorithmHint, "RSA_SHA256", StringComparison.OrdinalIgnoreCase) || string.Equals(algorithmHint, "AUTO", StringComparison.OrdinalIgnoreCase))
            {
                if (TryVerifyRsa(publicKey, hash, signature, out var error))
                {
                    return (true, "RSA_SHA256");
                }

                lastError = AppendReason(lastError, error);

                if (string.Equals(algorithmHint, "RSA_SHA256", StringComparison.OrdinalIgnoreCase))
                {
                    return (false, string.IsNullOrEmpty(error) ? "RSA verification failed." : error);
                }
            }

            return (false, string.IsNullOrEmpty(lastError) ? "Signature verification failed." : lastError);
        }

        private static bool TryVerifyEcdsa(IBuffer publicKey, IBuffer hash, IBuffer signature, out string reason)
        {
            try
            {
                var provider = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.EcdsaSha256);
                var blobTypes = new[]
                {
                    CryptographicPublicKeyBlobType.BCryptEccPublicBlob,
                    CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo
                };

                foreach (var blobType in blobTypes)
                {
                    try
                    {
                        var key = provider.ImportPublicKey(publicKey, blobType);
                        if (key != null)
                        {
                            if (CryptographicEngine.VerifySignature(key, hash, signature))
                            {
                                reason = string.Empty;
                                return true;
                            }
                            reason = "ECDSA signature mismatch.";
                            return false;
                        }
                    }
                    catch
                    {
                        // Try next blob type
                    }
                }

                reason = "ECDSA public key import failed.";
                return false;
            }
            catch (Exception ex)
            {
                reason = $"ECDSA verification error: {ex.Message}";
                return false;
            }
        }

        private static bool TryVerifyRsa(IBuffer publicKey, IBuffer hash, IBuffer signature, out string reason)
        {
            try
            {
                var provider = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaSignPkcs1Sha256);
                var blobTypes = new[]
                {
                    CryptographicPublicKeyBlobType.Capi1PublicKey,
                    CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo
                };

                foreach (var blobType in blobTypes)
                {
                    try
                    {
                        var key = provider.ImportPublicKey(publicKey, blobType);
                        if (key != null)
                        {
                            if (CryptographicEngine.VerifySignature(key, hash, signature))
                            {
                                reason = string.Empty;
                                return true;
                            }
                            reason = "RSA signature mismatch.";
                            return false;
                        }
                    }
                    catch
                    {
                        // Continue trying other blob representations
                    }
                }

                reason = "RSA public key import failed.";
                return false;
            }
            catch (Exception ex)
            {
                reason = $"RSA verification error: {ex.Message}";
                return false;
            }
        }

        private static string AppendReason(string current, string next)
        {
            if (string.IsNullOrWhiteSpace(next))
            {
                return current;
            }

            if (string.IsNullOrWhiteSpace(current))
            {
                return next;
            }

            return current + " | " + next;
        }
    }
}
