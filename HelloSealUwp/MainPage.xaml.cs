// SECURITY WARNING (PoC): Secret is stored in plaintext in app local storage. This is INSECURE and for demo only.
// This PoC uses ZERO ENCRYPTION. Only Windows Hello signature verification gates access.
using System;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using HelloSealUwp.Models;
using HelloSealUwp.Services;

namespace HelloSealUwp
{
    public sealed partial class MainPage : Page
    {
        private readonly HelloStore _store = new HelloStore();
        private readonly HelloHello _hello = new HelloHello();
        private readonly CryptoVerify _verify = new CryptoVerify();

        public MainPage()
        {
            InitializeComponent();
        }

        private async void OnEnrollClicked(object sender, RoutedEventArgs e)
        {
            EnrollStatusTextBlock.Text = string.Empty;
            UnlockStatusTextBlock.Text = string.Empty;
            SecretOutputTextBlock.Text = string.Empty;

            try
            {
                if (!await _hello.IsSupportedAsync())
                {
                    EnrollStatusTextBlock.Text = "Windows Hello is not available. Configure Windows Hello and try again.";
                    return;
                }

                var keyName = string.IsNullOrWhiteSpace(EnrollKeyNameTextBox.Text) ? "HelloSealKey" : EnrollKeyNameTextBox.Text.Trim();
                var secret = EnrollSecretTextBox.Text ?? string.Empty;

                var (_, publicKeyBuffer) = await _hello.EnrollAsync(keyName);
                var algorithm = DetectAlgorithm(publicKeyBuffer);
                var blob = new HelloBlob
                {
                    KeyName = keyName,
                    Algorithm = algorithm,
                    PublicKeyBase64 = CryptographicBuffer.EncodeToBase64String(publicKeyBuffer),
                    SecretPlaintext = secret
                };

                await _store.SaveAsync(blob);
                EnrollStatusTextBlock.Text = "Enrolled. Stored to local storage.";
            }
            catch (OperationCanceledException)
            {
                EnrollStatusTextBlock.Text = "Windows Hello enrollment canceled by user.";
            }
            catch (Exception ex)
            {
                EnrollStatusTextBlock.Text = $"Enrollment failed: {ex.Message}";
            }
        }

        private async void OnUnlockClicked(object sender, RoutedEventArgs e)
        {
            UnlockStatusTextBlock.Text = string.Empty;
            SecretOutputTextBlock.Text = string.Empty;

            try
            {
                var blob = await _store.LoadAsync();
                if (blob == null)
                {
                    UnlockStatusTextBlock.Text = "No enrollment found. Enroll first.";
                    return;
                }

                var requestedKeyName = string.IsNullOrWhiteSpace(UnlockKeyNameTextBox.Text) ? blob.KeyName : UnlockKeyNameTextBox.Text.Trim();
                if (!string.Equals(requestedKeyName, blob.KeyName, StringComparison.Ordinal))
                {
                    UnlockStatusTextBlock.Text = $"Stored key name is '{blob.KeyName}'. Update the unlock key name and try again.";
                    return;
                }

                var key = await _hello.OpenAsync(blob.KeyName);
                var challenge = CryptographicBuffer.GenerateRandom(32);
                var signature = await _hello.SignAsync(key, challenge);

                var verification = _verify.VerifySignature(blob.PublicKeyBase64, challenge, signature, blob.Algorithm);
                if (verification.IsValid)
                {
                    SecretOutputTextBlock.Text = blob.SecretPlaintext;
                    UnlockStatusTextBlock.Text = "Unlock successful.";
                }
                else
                {
                    UnlockStatusTextBlock.Text = $"Unlock failed: {verification.Reason}";
                }
            }
            catch (OperationCanceledException)
            {
                UnlockStatusTextBlock.Text = "Hello cancelled by user.";
            }
            catch (Exception ex)
            {
                UnlockStatusTextBlock.Text = $"Unlock failed: {ex.Message}";
            }
        }

        private string DetectAlgorithm(IBuffer publicKey)
        {
            try
            {
                var eccProvider = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.EcdsaSha256);
                foreach (var blobType in new[] { CryptographicPublicKeyBlobType.BCryptEccPublicBlob, CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo })
                {
                    try
                    {
                        var key = eccProvider.ImportPublicKey(publicKey, blobType);
                        if (key != null)
                        {
                            return "ECDSA_P256";
                        }
                    }
                    catch
                    {
                        // Ignore and try next
                    }
                }
            }
            catch
            {
                // Ignore detection failure
            }

            try
            {
                var rsaProvider = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaSignPkcs1Sha256);
                foreach (var blobType in new[] { CryptographicPublicKeyBlobType.Capi1PublicKey, CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo })
                {
                    try
                    {
                        var key = rsaProvider.ImportPublicKey(publicKey, blobType);
                        if (key != null)
                        {
                            return "RSA_SHA256";
                        }
                    }
                    catch
                    {
                        // Ignore and try next
                    }
                }
            }
            catch
            {
                // Ignore detection failure
            }

            return "AUTO";
        }
    }
}
