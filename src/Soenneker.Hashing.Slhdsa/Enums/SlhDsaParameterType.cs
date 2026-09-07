using Soenneker.Gen.EnumValues;

namespace Soenneker.Hashing.Slhdsa.Enums;

/// <summary>
/// Currently supported SLH-DSA parameter sets.
/// </summary>
[EnumValue<string>]
public sealed partial class SlhDsaParameterType
{
    public static readonly SlhDsaParameterType SLH_DSA_SHA2_128S = new("SLH-DSA-SHA2-128S");
    public static readonly SlhDsaParameterType SLH_DSA_SHAKE_128S = new("SLH-DSA-SHAKE-128S");
    public static readonly SlhDsaParameterType SLH_DSA_SHA2_128F = new("SLH-DSA-SHA2-128F");
    public static readonly SlhDsaParameterType SLH_DSA_SHAKE_128F = new("SLH-DSA-SHAKE-128F");
    public static readonly SlhDsaParameterType SLH_DSA_SHA2_192S = new("SLH-DSA-SHA2-192S");
    public static readonly SlhDsaParameterType SLH_DSA_SHAKE_192S = new("SLH-DSA-SHAKE-192S");
    public static readonly SlhDsaParameterType SLH_DSA_SHA2_192F = new("SLH-DSA-SHA2-192F");
    public static readonly SlhDsaParameterType SLH_DSA_SHAKE_192F = new("SLH-DSA-SHAKE-192F");
    public static readonly SlhDsaParameterType SLH_DSA_SHA2_256S = new("SLH-DSA-SHA2-256S");
    public static readonly SlhDsaParameterType SLH_DSA_SHAKE_256S = new("SLH-DSA-SHAKE-256S");
    public static readonly SlhDsaParameterType SLH_DSA_SHA2_256F = new("SLH-DSA-SHA2-256F");
    public static readonly SlhDsaParameterType SLH_DSA_SHAKE_256F = new("SLH-DSA-SHAKE-256F");
    public static readonly SlhDsaParameterType SLH_DSA_SHA2_128S_WITH_SHA256 = new("SLH-DSA-SHA2-128S-WITH-SHA256");
    public static readonly SlhDsaParameterType SLH_DSA_SHAKE_128S_WITH_SHAKE128 = new("SLH-DSA-SHAKE-128S-WITH-SHAKE128");
    public static readonly SlhDsaParameterType SLH_DSA_SHA2_128F_WITH_SHA256 = new("SLH-DSA-SHA2-128F-WITH-SHA256");
    public static readonly SlhDsaParameterType SLH_DSA_SHAKE_128F_WITH_SHAKE128 = new("SLH-DSA-SHAKE-128F-WITH-SHAKE128");
    public static readonly SlhDsaParameterType SLH_DSA_SHA2_192S_WITH_SHA512 = new("SLH-DSA-SHA2-192S-WITH-SHA512");
    public static readonly SlhDsaParameterType SLH_DSA_SHAKE_192S_WITH_SHAKE256 = new("SLH-DSA-SHAKE-192S-WITH-SHAKE256");
    public static readonly SlhDsaParameterType SLH_DSA_SHA2_192F_WITH_SHA512 = new("SLH-DSA-SHA2-192F-WITH-SHA512");
    public static readonly SlhDsaParameterType SLH_DSA_SHAKE_192F_WITH_SHAKE256 = new("SLH-DSA-SHAKE-192F-WITH-SHAKE256");
    public static readonly SlhDsaParameterType SLH_DSA_SHA2_256S_WITH_SHA512 = new("SLH-DSA-SHA2-256S-WITH-SHA512");
    public static readonly SlhDsaParameterType SLH_DSA_SHAKE_256S_WITH_SHAKE256 = new("SLH-DSA-SHAKE-256S-WITH-SHAKE256");
    public static readonly SlhDsaParameterType SLH_DSA_SHA2_256F_WITH_SHA512 = new("SLH-DSA-SHA2-256F-WITH-SHA512");
    public static readonly SlhDsaParameterType SLH_DSA_SHAKE_256F_WITH_SHAKE256 = new("SLH-DSA-SHAKE-256F-WITH-SHAKE256");
}
