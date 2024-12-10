using FluentAssertions;
using Soenneker.Tests.FixturedUnit;
using Xunit;
using Xunit.Abstractions;

namespace Soenneker.Hashing.Slhdsa.Tests;

[Collection("Collection")]
public class SlhDsaHashingUtilTests : FixturedUnitTest
{
    public SlhDsaHashingUtilTests(Fixture fixture, ITestOutputHelper output) : base(fixture, output)
    {
    }

    [Fact]
    public void GenerateKeyPair_ShouldReturnValidKeys()
    {
        // Act
        (string privateKey, string publicKey) = SlhDsaHashingUtil.GenerateKeyPair();

        // Assert
        privateKey.Should().NotBeNullOrEmpty("private key must be generated");
        publicKey.Should().NotBeNullOrEmpty("public key must be generated");
        privateKey.Should().NotBe(publicKey, "private and public keys should be different");
    }

    [Fact]
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

    [Fact]
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

    [Fact]
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

    [Fact]
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
