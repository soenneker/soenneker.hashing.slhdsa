[![](https://img.shields.io/nuget/v/soenneker.hashing.slhdsa.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.slhdsa/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.slhdsa/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.hashing.slhdsa/actions/workflows/publish-package.yml)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.slhdsa/build-and-test.yml?style=for-the-badge&label=build)](https://github.com/soenneker/soenneker.hashing.slhdsa/actions/workflows/build-and-test.yml)
[![](https://img.shields.io/nuget/dt/soenneker.hashing.slhdsa.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.slhdsa/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.slhdsa/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.hashing.slhdsa/actions/workflows/codeql.yml)

# Soenneker.Hashing.Slhdsa

Generates SLH-DSA post-quantum key pairs, signs UTF-8 messages, and verifies signatures using Bouncy Castle. This is a digital-signature utility, not a password-hashing API.

## Installation

```bash
dotnet add package Soenneker.Hashing.Slhdsa
```

## Generate keys, sign, and verify

```csharp
using Soenneker.Hashing.Slhdsa;

(string privateKey, string publicKey) = SlhDsaHashingUtil.GenerateKeyPair();

string signature = SlhDsaHashingUtil.SignMessage(
    "release-manifest-v42",
    privateKey);

bool valid = SlhDsaHashingUtil.VerifySignature(
    "release-manifest-v42",
    signature,
    publicKey);
```

Keys and signatures are returned as Base64 strings. The private key contains a DER-encoded PKCS#8 `PrivateKeyInfo`; the public key contains a DER-encoded X.509 `SubjectPublicKeyInfo`.

## Choose a parameter set

```csharp
using Soenneker.Hashing.Slhdsa.Enums;

const SlhDsaParameterType parameters = SlhDsaParameterType.SLH_DSA_SHA2_192S;

(string privateKey, string publicKey) =
    SlhDsaHashingUtil.GenerateKeyPair(parameters);

string signature = SlhDsaHashingUtil.SignMessage(message, privateKey, parameters);
bool valid = SlhDsaHashingUtil.VerifySignature(message, signature, publicKey, parameters);
```

The same parameter set must be used for key generation, signing, and verification. The default is `SLH_DSA_SHAKE_128F`. In the enum names, `128`, `192`, and `256` identify security categories; `F` variants favor faster signing with larger signatures, while `S` variants favor smaller signatures with slower signing.

The overloads accepting Bouncy Castle’s `SlhDsaParameters` or a signer-name string are available for advanced interoperability scenarios. Prefer the enum overloads when both sides use this package.

`VerifySignature()` returns `false` for malformed Base64, invalid keys, invalid signatures, unsupported signer names, and encoded inputs above its defensive size limits. Signing and key generation surface configuration/key errors. Decoded private-key and message buffers are cleared after signing, but the returned private-key string is immutable managed data: protect it with an appropriate secret store, restrict access, and never log it.
