using System.Net;

namespace FirewallTutor.Models;

public sealed class NetworkPacket
{
    public int Id { get; }
    public string SourceIp { get; }
    public string DestinationIp { get; }
    public int SourcePort { get; }
    public int DestinationPort { get; }
    public string Protocol { get; }
    public string Payload { get; }
    public DateTime CreatedAt { get; }

    public NetworkPacket(int id, string sourceIp, string destinationIp, int sourcePort, int destinationPort, string protocol, string payload)
    {
        if (!IsValidIp(sourceIp)) throw new ArgumentException("Invalid source IP address.", nameof(sourceIp));
        if (!IsValidIp(destinationIp)) throw new ArgumentException("Invalid destination IP address.", nameof(destinationIp));
        if (!IsValidPort(sourcePort)) throw new ArgumentException("Source port must be between 1 and 65535.", nameof(sourcePort));
        if (!IsValidPort(destinationPort)) throw new ArgumentException("Destination port must be between 1 and 65535.", nameof(destinationPort));
        if (string.IsNullOrWhiteSpace(protocol)) throw new ArgumentException("Protocol is required.", nameof(protocol));

        Id = id;
        SourceIp = sourceIp.Trim();
        DestinationIp = destinationIp.Trim();
        SourcePort = sourcePort;
        DestinationPort = destinationPort;
        Protocol = protocol.Trim().ToUpperInvariant();
        Payload = payload.Trim();
        CreatedAt = DateTime.Now;
    }

    public static bool IsValidIp(string value)
    {
        return IPAddress.TryParse(value, out IPAddress? address)
               && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
    }

    public static bool IsValidPort(int value) => value is >= 1 and <= 65535;

    public override string ToString()
    {
        return $"#{Id} {SourceIp}:{SourcePort} -> {DestinationIp}:{DestinationPort} {Protocol} Payload={Payload}";
    }
}
