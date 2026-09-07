using FirewallTutor.Models;

namespace FirewallTutor.Services;

public static class CsvStorage
{
    public static void SaveRules(string path, IEnumerable<FirewallRule> rules)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
        using StreamWriter writer = new(path);
        writer.WriteLine("Id,Field,Value,Action,Enabled,Description");
        foreach (FirewallRule rule in rules)
        {
            writer.WriteLine($"{rule.Id},{rule.Field},{Escape(rule.Value)},{rule.Action},{rule.Enabled},{Escape(rule.Description)}");
        }
    }

    public static void SavePackets(string path, IEnumerable<NetworkPacket> packets)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
        using StreamWriter writer = new(path);
        writer.WriteLine("Id,SourceIp,DestinationIp,SourcePort,DestinationPort,Protocol,Payload");
        foreach (NetworkPacket packet in packets)
        {
            writer.WriteLine($"{packet.Id},{packet.SourceIp},{packet.DestinationIp},{packet.SourcePort},{packet.DestinationPort},{packet.Protocol},{Escape(packet.Payload)}");
        }
    }

    public static void SaveResults(string path, IEnumerable<EvaluationResult> results)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
        using StreamWriter writer = new(path);
        writer.WriteLine("PacketId,SourceIp,DestinationIp,Protocol,Decision,Rule,Reason");
        foreach (EvaluationResult result in results)
        {
            writer.WriteLine($"{result.Packet.Id},{result.Packet.SourceIp},{result.Packet.DestinationIp},{result.Packet.Protocol},{result.FinalAction},{result.MatchedRuleId},{result.Reason}");
        }
    }

    private static string Escape(string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
        {
            return $"\"{value.Replace("\"", "\"\"")}\"";
        }

        return value;
    }
}
