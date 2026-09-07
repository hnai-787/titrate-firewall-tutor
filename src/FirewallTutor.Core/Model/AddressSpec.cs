using System.Text;

namespace FirewallTutor.Core.Model;

/// <summary>
/// An address match expression: "any", a single host, or a base address
/// plus a Cisco-style wildcard mask (1 bits are "don't care"). Unlike
/// fwlint's box algebra, this only ever needs to test membership of one
/// concrete packet address at a time, so -- unlike fwlint -- there is no
/// need to reject discontiguous wildcard masks here: bit-level membership
/// testing works identically either way, and showing a discontiguous mask
/// is actually a good teaching moment about what wildcard bits really mean.
/// </summary>
public sealed class AddressSpec
{
    public bool IsAny { get; }
    public uint Base { get; }
    public uint Wildcard { get; }
    public string DisplayText { get; }

    private AddressSpec(bool isAny, uint baseAddr, uint wildcard, string displayText)
    {
        IsAny = isAny;
        Base = baseAddr;
        Wildcard = wildcard;
        DisplayText = displayText;
    }

    public static AddressSpec Any() => new(true, 0, 0xFFFFFFFF, "any");

    public static AddressSpec Host(uint address) => new(false, address, 0, $"host {FormatIp(address)}");

    public static AddressSpec WildcardMask(uint baseAddr, uint wildcard) =>
        new(false, baseAddr, wildcard, $"{FormatIp(baseAddr)} {FormatIp(wildcard)}");

    public static AddressSpec Cidr(uint network, int prefixLength)
    {
        uint mask = prefixLength == 0 ? 0u : 0xFFFFFFFFu << (32 - prefixLength);
        uint wildcard = ~mask;
        return new AddressSpec(false, network, wildcard, $"{FormatIp(network)}/{prefixLength}");
    }

    public bool Matches(uint address) => IsAny || (address & ~Wildcard) == (Base & ~Wildcard);

    /// <summary>
    /// A short, human-readable explanation of why a specific address did
    /// or didn't match -- used to answer "why did this fail?" rather than
    /// just "it failed" (see README "Design decisions").
    /// </summary>
    public string Explain(uint address)
    {
        if (IsAny) return "any address matches";
        if (Wildcard == 0) return Matches(address) ? "matches the required host exactly" : "does not match the required host";

        bool matched = Matches(address);
        return matched
            ? $"matches {DisplayText} (bits outside the wildcard agree)"
            : $"does not match {DisplayText} (differs in a bit position outside the wildcard)";
    }

    public string BitBreakdown(uint address)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"  packet   {ToBinary(address)}  ({FormatIp(address)})");
        sb.AppendLine($"  base     {ToBinary(Base)}  ({FormatIp(Base)})");
        sb.AppendLine($"  wildcard {ToBinary(Wildcard)}  ({FormatIp(Wildcard)})  (1 = ignore this bit)");
        return sb.ToString();
    }

    private static string ToBinary(uint value)
    {
        string bits = Convert.ToString(value, 2).PadLeft(32, '0');
        return string.Join('.', new[] { bits[0..8], bits[8..16], bits[16..24], bits[24..32] });
    }

    public static string FormatIp(uint value) =>
        $"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}";

    public static bool TryParseIp(string text, out uint address)
    {
        address = 0;
        string[] parts = text.Trim().Split('.');
        if (parts.Length != 4) return false;

        uint result = 0;
        foreach (string part in parts)
        {
            if (!byte.TryParse(part, out byte octet)) return false;
            result = (result << 8) | octet;
        }
        address = result;
        return true;
    }

    public override string ToString() => DisplayText;
}
