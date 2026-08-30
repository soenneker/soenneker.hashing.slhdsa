using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Soenneker.Extensions.Arrays.Bytes;
using Soenneker.Extensions.String;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using Soenneker.Hashing.Slhdsa.Enums;
using System.Reflection;
using System.Diagnostics.Contracts;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Soenneker.Hashing.Slhdsa;

/// <summary>
/// Generates SLH-DSA keys, signs UTF-8 messages, and verifies signatures.
/// </summary>
public static class SlhDsaHashingUtil
{
    private static readonly ConcurrentDictionary<SlhDsaParameterType, SlhDsaParameters> _parametersCache = new();

    /// <summary>
    /// Generates a new SLH-DSA key pair.
    /// </summary>
    /// <param name="parameterType">Parameter Type for the generate key pair operation.</param>
    /// <returns>Tuple containing the private and public keys as Base64 strings.</returns>
    public static (string PrivateKey, string PublicKey) GenerateKeyPair(SlhDsaParameterType parameterType = SlhDsaParameterType.SLH_DSA_SHAKE_128F)
    {
        SlhDsaParameters slhDsaParameters = GetParametersFromEnum(parameterType);

        return GenerateKeyPair(slhDsaParameters);
    }

    /// <summary>
    /// Generates a new SLH-DSA key pair.
    /// </summary>
    /// <param name="slhDsaParameters">Slh Dsa Parameters for the generate key pair operation.</param>
    /// <returns>Tuple containing the private and public keys as Base64 strings.</returns>
    public static (string PrivateKey, string PublicKey) GenerateKeyPair(SlhDsaParameters slhDsaParameters)
    {
        var secureRandom = new SecureRandom();

        // Initialize the key pair generator with specific SLH-DSA parameters
        var parameters = new SlhDsaKeyGenerationParameters(secureRandom, slhDsaParameters);

        // Initialize the key pair generator
        IAsymmetricCipherKeyPairGenerator keyPairGenerator = GeneratorUtilities.GetKeyPairGenerator("SLH-DSA");
        keyPairGenerator.Init(parameters);

        // Generate key pair
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

        // Serialize keys and encode as Base64
        string privateKeyBase64 = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private).GetEncoded().ToBase64String();
        string publicKeyBase64 = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).GetEncoded().ToBase64String();

        return (privateKeyBase64, publicKeyBase64);
    }

    /// <summary>
    /// Signs a message using the provided SLH-DSA private key.
    /// </summary>
    /// <param name="message">The message to sign.</param>
    /// <param name="privateKeyBase64">The private key in Base64 format.</param>
    /// <param name="parameterType"></param>
    /// <returns>The signature as a Base64 string.</returns>
    public static string SignMessage(string message, string privateKeyBase64, SlhDsaParameterType parameterType = SlhDsaParameterType.SLH_DSA_SHAKE_128F)
    {
        return SignMessage(message, privateKeyBase64, GetFormalNameForParameter(parameterType));
    }

    /// <summary>
    /// Signs a message using the provided SLH-DSA private key.
    /// </summary>
    /// <param name="message">The message to sign.</param>
    /// <param name="privateKeyBase64">The private key in Base64 format.</param>
    /// <param name="parameterType"></param>
    /// <returns>The signature as a Base64 string.</returns>
    public static string SignMessage(string message, string privateKeyBase64, string parameterType)
    {
        byte[] privateKeyBytes = privateKeyBase64.ToBytesFromBase64();
        byte[] messageBytes = message.ToBytes();
        byte[] signature = [];

        try
        {
            AsymmetricKeyParameter privateKey = PrivateKeyFactory.CreateKey(privateKeyBytes);
            ISigner signer = SignerUtilities.GetSigner(parameterType);
            signer.Init(true, privateKey);

            signer.BlockUpdate(messageBytes, 0, messageBytes.Length);
            signature = signer.GenerateSignature();

            return signature.ToBase64String();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKeyBytes);
            CryptographicOperations.ZeroMemory(messageBytes);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    /// <summary>
    /// Verifies a signature against a message using the provided SLH-DSA public key.
    /// </summary>
    /// <param name="message">The original message.</param>
    /// <param name="signatureBase64">The signature in Base64 format.</param>
    /// <param name="publicKeyBase64">The public key in Base64 format.</param>
    /// <param name="parameterType"></param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    [Pure]
    public static bool VerifySignature(string message, string signatureBase64, string publicKeyBase64, string parameterType)
    {
        if (message is null || signatureBase64 is null || publicKeyBase64 is null || parameterType is null || signatureBase64.Length > 150_000 ||
            publicKeyBase64.Length > 4096 || parameterType.Length > 64)
        {
            return false;
        }

        byte[] publicKeyBytes = [];
        byte[] messageBytes = [];
        byte[] signature = [];

        try
        {
            publicKeyBytes = publicKeyBase64.ToBytesFromBase64();
            AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(publicKeyBytes);
            ISigner signer = SignerUtilities.GetSigner(parameterType);
            signer.Init(false, publicKey);

            messageBytes = message.ToBytes();
            signer.BlockUpdate(messageBytes, 0, messageBytes.Length);

            signature = signatureBase64.ToBytesFromBase64();

            return signer.VerifySignature(signature);
        }
        catch
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKeyBytes);
            CryptographicOperations.ZeroMemory(messageBytes);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    /// <summary>
    /// Verifies a signature against a message using the provided SLH-DSA public key.
    /// </summary>
    /// <param name="message">The original message.</param>
    /// <param name="signatureBase64">The signature in Base64 format.</param>
    /// <param name="publicKeyBase64">The public key in Base64 format.</param>
    /// <param name="parameterType"></param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    [Pure]
    public static bool VerifySignature(string message, string signatureBase64, string publicKeyBase64, SlhDsaParameterType parameterType = SlhDsaParameterType.SLH_DSA_SHAKE_128F)
    {
        return VerifySignature(message, signatureBase64, publicKeyBase64, GetFormalNameForParameter(parameterType));
    }

    private static SlhDsaParameters GetParametersFromEnum(SlhDsaParameterType parameterType)
    {
        // Use or add the parameter to the cache
        return _parametersCache.GetOrAdd(parameterType, key =>
        {
            string parameterName = key.ToString().ToLowerInvariantFast();

            // Reflectively retrieve the field
            FieldInfo? fieldInfo = typeof(SlhDsaParameters).GetField(parameterName, BindingFlags.Public | BindingFlags.Static);

            if (fieldInfo == null)
                throw new ArgumentException($"Invalid SLH-DSA parameter type: {parameterName}");

            return (SlhDsaParameters) fieldInfo.GetValue(null)!;
        });
    }

    private static string GetFormalNameForParameter(SlhDsaParameterType parameterType)
    {
        return parameterType.ToString().Replace("_", "-");
    }
}
