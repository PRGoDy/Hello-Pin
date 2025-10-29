SECURITY WARNING (PoC): Secret is stored in plaintext in app local storage. This is INSECURE and for demo only.
This PoC uses ZERO ENCRYPTION. Only Windows Hello signature verification gates access.

# HelloSeal UWP

HelloSeal UWP is a proof-of-concept Universal Windows Platform application that gates access to a plaintext secret using Windows Hello Key Credential signatures. The secret is stored exactly as provided in application local storage, and the only gate is verifying a Windows Hello digital signature over a random challenge.

## Project structure

```
HelloSealUwp/
  HelloSealUwp.csproj
  App.xaml
  App.xaml.cs
  MainPage.xaml
  MainPage.xaml.cs
  Models/HelloBlob.cs
  Services/HelloStore.cs
  Services/HelloHello.cs
  Services/CryptoVerify.cs
```

## Requirements

* Windows 10 or Windows 11 with Windows Hello (PIN, biometric, or security key) configured.
* Visual Studio 2022 with UWP workload installed.

## Running the demo

1. Open `HelloSealUwp.sln` (create a solution and add the project, or open the project directly) in Visual Studio.
2. Build and deploy the app to a local machine that has Windows Hello configured.
3. In the **Enroll** section:
   * Enter the secret plaintext (for example, `Hello world`).
   * Enter a key name (default `HelloSealKey`).
   * Select **Enroll**. Approve the Windows Hello prompt. A file named `helloseal.json` appears in the app's local storage containing the plaintext secret and the Windows Hello public key in Base64.
4. In the **Unlock** section:
   * Ensure the key name matches the stored key (`HelloSealKey` by default).
   * Select **Unlock** and complete the Windows Hello prompt. On success the exact plaintext secret is displayed with no additional formatting.

## Negative scenarios

* Canceling the Windows Hello prompt during enrollment or unlock shows a clear status message.
* Changing the key name or deleting `helloseal.json` will cause unlock to fail with an informative message.
* Attempting to unlock from a different Windows user profile fails because the Key Credential is unavailable.

## Security disclaimer

This proof of concept intentionally stores the secret in plaintext and performs no encryption, obfuscation, compression, or key wrapping. Windows Hello signature verification is the only protection layer. For production scenarios, replace the plaintext storage with a secure mechanism such as DPAPI, NCrypt, or Windows Hello key wrapping.
