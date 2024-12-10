[![](https://img.shields.io/nuget/v/soenneker.hashing.slhdsa.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.slhdsa/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.slhdsa/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.hashing.slhdsa/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.hashing.slhdsa.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.slhdsa/)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Hashing.Slhdsa
### A utility library for SLH-DSA hashing and verification

A compact and lightweight library for **SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)**, a post-quantum cryptographic standard providing robust security against classical and quantum attacks. SLH-DSA uses hash-based cryptography to ensure secure key generation, message signing, and signature verification.

## Features

- Generate **SLH-DSA key pairs**.
- Sign and verify messages.
- Supports multiple parameter sets (e.g., SHAKE-128F, SHA2-128F).
- Thread-safe supporting concurrency.
- Tests included.

## Installation

```
dotnet add package Soenneker.Hashing.Slhdsa
```

## Usage

### 1. Generate a public and private key pair
```csharp
(string privateKey, string publicKey) = SlhDsaHashingUtil.GenerateKeyPair(); // Keys are Base64 strings
```

### 2. Sign the payload with the private key
```csharp
string signature = SlhDsaHashingUtil.SignMessage("Hello, SLH-DSA!", privateKey); // Signaure is a Base64 string
```

### 3. Verify the signature with the public key
```csharp
bool isValid = SlhDsaHashingUtil.VerifySignature("Hello, SLH-DSA!", signature, publicKey);
```

### How to specify the optional parameter set:
```csharp
var parameterSet = SlhDsaParameterType.SLH_DSA_SHAKE_128F;

(string privateKey, string publicKey) = SlhDsaHashingUtil.GenerateKeyPair(parameterSet);
string signature = SlhDsaHashingUtil.SignMessage("Hello, SLH-DSA!", privateKey, parameterSet);
bool isValid = SlhDsaHashingUtil.VerifySignature("Hello, SLH-DSA!", signature, publicKey, parameterSet);
```