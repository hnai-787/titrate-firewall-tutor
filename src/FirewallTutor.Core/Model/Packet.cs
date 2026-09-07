namespace FirewallTutor.Core.Model;

public sealed class Packet
{
    public required string Protocol { get; init; }
    public required uint SourceAddress { get; init; }
    public required int SourcePort { get; init; }
    public required uint DestinationAddress { get; init; }
    public required int DestinationPort { get; init; }

    public byte ProtocolNumber => ProtocolSpec.Named(Protocol).Value;

    public string DisplayText =>
        $"{Protocol.ToUpperInvariant()} {AddressSpec.FormatIp(SourceAddress)}:{SourcePort} -> " +
        $"{AddressSpec.FormatIp(DestinationAddress)}:{DestinationPort}";
}
