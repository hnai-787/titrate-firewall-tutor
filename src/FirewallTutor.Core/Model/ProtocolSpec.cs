namespace FirewallTutor.Core.Model;

public sealed class ProtocolSpec
{
    public bool IsAny { get; }
    public byte Value { get; }
    public string DisplayText { get; }

    private ProtocolSpec(bool isAny, byte value, string displayText)
    {
        IsAny = isAny;
        Value = value;
        DisplayText = displayText;
    }

    public static ProtocolSpec Any() => new(true, 0, "ip");

    public static ProtocolSpec Named(string name)
    {
        string lower = name.Trim().ToLowerInvariant();
        return lower switch
        {
            "ip" or "any" => Any(),
            "tcp" => new ProtocolSpec(false, 6, "tcp"),
            "udp" => new ProtocolSpec(false, 17, "udp"),
            "icmp" => new ProtocolSpec(false, 1, "icmp"),
            _ when byte.TryParse(lower, out byte numeric) => new ProtocolSpec(false, numeric, lower),
            _ => throw new FormatException($"Unsupported protocol \"{name}\"")
        };
    }

    public bool Matches(byte protocol) => IsAny || protocol == Value;

    public static bool IsPortCapable(string protocolText)
    {
        string lower = protocolText.Trim().ToLowerInvariant();
        return lower is "tcp" or "udp";
    }

    public override string ToString() => DisplayText;
}
