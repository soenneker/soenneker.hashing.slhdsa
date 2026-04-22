using AwesomeAssertions;
using Soenneker.Tests.HostedUnit;


namespace Soenneker.Hashing.Slhdsa.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public class SlhDsaHashingUtilTests : HostedUnitTest
{
    public SlhDsaHashingUtilTests(Host host) : base(host)
    {
    }

    [Test]
    public void GenerateKeyPair_ShouldReturnValidKeys()
    {
        // Act
        (string privateKey, string publicKey) = SlhDsaHashingUtil.GenerateKeyPair();

        // Assert
        privateKey.Should().NotBeNullOrEmpty("private key must be generated");
        publicKey.Should().NotBeNullOrEmpty("public key must be generated");
        privateKey.Should().NotBe(publicKey, "private and public keys should be different");
    }

    [Test]
    public void SignMessage_ShouldReturnValidSignature()
    {
        // Arrange
        (string privateKey, string publicKey) = SlhDsaHashingUtil.GenerateKeyPair();
        const string message = "Test message for signing";

        // Act
        string signature = SlhDsaHashingUtil.SignMessage(message, privateKey);

        // Assert
        signature.Should().NotBeNullOrEmpty("signature must be generated");
        signature.Should().NotBe(message, "signature should not match the original message");
    }

    [Test]
    public void VerifySignature_ValidSignature_ShouldReturnTrue()
    {
        // Arrange
        (string privateKey, string publicKey) = SlhDsaHashingUtil.GenerateKeyPair();
        const string message = "Test message for verification";
        string signature = SlhDsaHashingUtil.SignMessage(message, privateKey);

        // Act
        bool isValid = SlhDsaHashingUtil.VerifySignature(message, signature, publicKey);

        // Assert
        isValid.Should().BeTrue("valid signature should be verified successfully");
    }

    [Test]
    public void VerifySignature_InvalidSignature_ShouldReturnFalse()
    {
        // Arrange
        (_, string publicKey) = SlhDsaHashingUtil.GenerateKeyPair();
        const string message = "Test message for verification";

        // Use a valid but random Base64 string as an invalid signature
        const string invalidSignature = "SGVsbG9Xb3JsZFNpZ25hdHVyZQ=="; // Base64 for "HelloWorldSignature"

        // Act
        bool isValid = SlhDsaHashingUtil.VerifySignature(message, invalidSignature, publicKey);

        // Assert
        isValid.Should().BeFalse("invalid signature should not be verified");
    }

    [Test]
    public void VerifySignature_WithModifiedMessage_ShouldReturnFalse()
    {
        // Arrange
        (string privateKey, string publicKey) = SlhDsaHashingUtil.GenerateKeyPair();
        const string originalMessage = "Original message";
        string signature = SlhDsaHashingUtil.SignMessage(originalMessage, privateKey);
        const string tamperedMessage = "Tampered message";

        // Act
        bool isValid = SlhDsaHashingUtil.VerifySignature(tamperedMessage, signature, publicKey);

        // Assert
        isValid.Should().BeFalse("signature should not verify if the message is altered");
    }
}
