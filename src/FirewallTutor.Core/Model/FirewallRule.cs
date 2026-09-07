namespace FirewallTutor.Core.Model;

public sealed class FirewallRule
{
    public int Ordinal { get; init; }
    public int SourceLine { get; init; }
    public RuleAction Action { get; init; }
    public required ProtocolSpec Protocol { get; init; }
    public required AddressSpec Source { get; init; }
    public required PortSpec SourcePort { get; init; }
    public required AddressSpec Destination { get; init; }
    public required PortSpec DestinationPort { get; init; }
    public string RawText { get; init; } = "";

    public bool IsPortCapable => Protocol.DisplayText is "tcp" or "udp";
}
