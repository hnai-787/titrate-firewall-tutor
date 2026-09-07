using System.Net;

namespace FirewallTutor.Models;

public sealed class FirewallRule
{
    public int Id { get; }
    public RuleField Field { get; }
    public string Value { get; }
    public RuleAction Action { get; }
    public bool Enabled { get; set; }
    public string Description { get; }

    public FirewallRule(int id, RuleField field, string value, RuleAction action, string description = "", bool enabled = true)
    {
        if (id <= 0) throw new ArgumentException("Rule ID must be greater than zero.", nameof(id));
        if (field != RuleField.Any && string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("Value is required unless the rule field is Any.", nameof(value));

        Id = id;
        Field = field;
        Value = value.Trim();
        Action = action;
        Description = description.Trim();
        Enabled = enabled;
    }

    public bool Matches(NetworkPacket packet)
    {
        if (!Enabled) return false;

        return Field switch
        {
            RuleField.Any => true,
            RuleField.SourceIp => MatchesIp(Value, packet.SourceIp),
            RuleField.DestinationIp => MatchesIp(Value, packet.DestinationIp),
            RuleField.SourcePort => MatchesPort(Value, packet.SourcePort),
            RuleField.DestinationPort => MatchesPort(Value, packet.DestinationPort),
            RuleField.Protocol => string.Equals(Value, packet.Protocol, StringComparison.OrdinalIgnoreCase),
            RuleField.PayloadContains => packet.Payload.Contains(Value, StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static bool MatchesPort(string ruleValue, int packetPort)
    {
        if (int.TryParse(ruleValue, out int singlePort))
        {
            return IsValidPort(singlePort) && packetPort == singlePort;
        }

        string[] range = ruleValue.Split('-', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (range.Length == 2 && int.TryParse(range[0], out int start) && int.TryParse(range[1], out int end))
        {
            if (!IsValidPort(start) || !IsValidPort(end) || start > end)
            {
                return false;
            }

            return packetPort >= start && packetPort <= end;
        }

        return false;
    }

    private static bool MatchesIp(string ruleValue, string packetIp)
    {
        string value = ruleValue.Trim();

        if (value.Contains('/'))
        {
            return MatchesCidr(value, packetIp);
        }

        if (value.Contains('-'))
        {
            return MatchesLastOctetRange(value, packetIp);
        }

        return string.Equals(value, packetIp, StringComparison.OrdinalIgnoreCase);
    }

    private static bool MatchesLastOctetRange(string ruleValue, string packetIp)
    {
        // Example: 192.168.1.10-20 means 192.168.1.10 through 192.168.1.20
        string[] rangeParts = ruleValue.Split('-', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (rangeParts.Length != 2) return false;
        if (!IPAddress.TryParse(packetIp, out IPAddress? packetAddress)) return false;

        string startIpText = rangeParts[0];
        if (!IPAddress.TryParse(startIpText, out IPAddress? startAddress)) return false;
        if (!int.TryParse(rangeParts[1], out int endLastOctet)) return false;

        byte[] packetBytes = packetAddress.GetAddressBytes();
        byte[] startBytes = startAddress.GetAddressBytes();

        if (packetBytes.Length != 4 || startBytes.Length != 4) return false;
        if (endLastOctet < 0 || endLastOctet > 255 || startBytes[3] > endLastOctet) return false;

        return packetBytes[0] == startBytes[0]
               && packetBytes[1] == startBytes[1]
               && packetBytes[2] == startBytes[2]
               && packetBytes[3] >= startBytes[3]
               && packetBytes[3] <= endLastOctet;
    }

    private static bool MatchesCidr(string cidr, string packetIp)
    {
        // Basic IPv4 CIDR support, example: 192.168.1.0/24
        string[] parts = cidr.Split('/', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2) return false;
        if (!IPAddress.TryParse(parts[0], out IPAddress? networkAddress)) return false;
        if (!IPAddress.TryParse(packetIp, out IPAddress? packetAddress)) return false;
        if (!int.TryParse(parts[1], out int prefixLength)) return false;
        if (prefixLength is < 0 or > 32) return false;

        byte[] networkBytes = networkAddress.GetAddressBytes();
        byte[] packetBytes = packetAddress.GetAddressBytes();
        if (networkBytes.Length != 4 || packetBytes.Length != 4) return false;

        uint network = ToUInt32(networkBytes);
        uint packet = ToUInt32(packetBytes);
        uint mask = prefixLength == 0 ? 0 : uint.MaxValue << (32 - prefixLength);

        return (network & mask) == (packet & mask);
    }

    private static uint ToUInt32(byte[] bytes)
    {
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    private static bool IsValidPort(int value)
    {
        return value is >= 1 and <= 65535;
    }

    public override string ToString()
    {
        return $"#{Id} {Field} {Value} => {Action} Enabled={Enabled}";
    }
}
