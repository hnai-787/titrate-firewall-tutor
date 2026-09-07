using FirewallTutor.Models;

namespace FirewallTutor.Services;

public sealed class FirewallEngine
{
    private readonly List<FirewallRule> _rules = new();
    private readonly List<NetworkPacket> _packets = new();
    private readonly List<string> _logs = new();

    public IReadOnlyList<FirewallRule> Rules => _rules.AsReadOnly();
    public IReadOnlyList<NetworkPacket> Packets => _packets.AsReadOnly();
    public IReadOnlyList<string> Logs => _logs.AsReadOnly();

    public RuleAction DefaultAction { get; set; } = RuleAction.Deny;
    public bool LoggingEnabled { get; set; } = true;

    public void AddRule(FirewallRule rule)
    {
        if (_rules.Any(r => r.Id == rule.Id))
            throw new InvalidOperationException($"Rule ID {rule.Id} already exists.");

        _rules.Add(rule);
        AddLog($"Added rule: {rule}");
    }

    public void RemoveRule(int ruleId)
    {
        FirewallRule? rule = _rules.FirstOrDefault(r => r.Id == ruleId);
        if (rule is null) return;

        _rules.Remove(rule);
        AddLog($"Removed rule #{ruleId}");
    }

    public void ClearRules()
    {
        _rules.Clear();
        AddLog("Cleared all rules");
    }

    public void AddPacket(NetworkPacket packet)
    {
        if (_packets.Any(p => p.Id == packet.Id))
            throw new InvalidOperationException($"Packet ID {packet.Id} already exists.");

        _packets.Add(packet);
        AddLog($"Added packet: {packet}");
    }

    public void RemovePacket(int packetId)
    {
        NetworkPacket? packet = _packets.FirstOrDefault(p => p.Id == packetId);
        if (packet is null) return;

        _packets.Remove(packet);
        AddLog($"Removed packet #{packetId}");
    }

    public void ClearPackets()
    {
        _packets.Clear();
        AddLog("Cleared all packets");
    }

    public void ClearLogs()
    {
        _logs.Clear();
        AddLog("Logs cleared");
    }

    public EvaluationResult Evaluate(NetworkPacket packet)
    {
        foreach (FirewallRule rule in _rules.Where(r => r.Enabled))
        {
            if (rule.Matches(packet))
            {
                AddLog($"Packet #{packet.Id} {rule.Action} by rule #{rule.Id}");
                return new EvaluationResult(packet, rule.Action, rule.Id, $"MATCHED_RULE_{rule.Id}");
            }
        }

        AddLog($"Packet #{packet.Id} {DefaultAction} by default policy");
        string reason = DefaultAction == RuleAction.Deny ? "DEFAULT_DENY" : "DEFAULT_ALLOW";
        return new EvaluationResult(packet, DefaultAction, 0, reason);
    }

    public List<EvaluationResult> EvaluateAll()
    {
        return _packets.Select(Evaluate).ToList();
    }

    public void LoadSampleRules()
    {
        ClearRules();
        AddRule(new FirewallRule(1, RuleField.SourceIp, "10.0.0.5", RuleAction.Deny, "Block known suspicious source"));
        AddRule(new FirewallRule(2, RuleField.DestinationIp, "192.168.1.10-20", RuleAction.Deny, "Block internal restricted range"));
        AddRule(new FirewallRule(3, RuleField.DestinationIp, "192.168.255.255", RuleAction.Allow, "Allow broadcast lab packet"));
        AddRule(new FirewallRule(4, RuleField.Protocol, "ICMP", RuleAction.Deny, "Block ping traffic"));
        AddRule(new FirewallRule(5, RuleField.Protocol, "UDP", RuleAction.Allow, "Allow UDP before later deny rule"));
        AddRule(new FirewallRule(6, RuleField.SourceIp, "172.16.5.0/24", RuleAction.Allow, "Allow trusted lab subnet"));
        AddRule(new FirewallRule(7, RuleField.DestinationIp, "8.8.8.8", RuleAction.Deny, "Block DNS to public resolver"));
        AddRule(new FirewallRule(8, RuleField.Protocol, "TCP", RuleAction.Allow, "Allow TCP as final protocol rule"));
    }

    public void LoadSamplePackets()
    {
        ClearPackets();
        AddPacket(new NetworkPacket(1, "10.0.0.5", "192.168.1.20", 5555, 80, "TCP", "A1B2C3D4"));
        AddPacket(new NetworkPacket(2, "157.165.1.10", "192.168.1.10", 4432, 443, "TCP", "F3462AC8BB76903C"));
        AddPacket(new NetworkPacket(3, "152.5.23.120", "192.168.255.255", 2000, 53, "UDP", "HELLO123"));
        AddPacket(new NetworkPacket(4, "112.15.9.20", "192.168.1.255", 8, 8, "ICMP", "PINGDATA"));
        AddPacket(new NetworkPacket(5, "172.16.5.25", "192.168.5.10", 4555, 8080, "TCP", "PAYLOAD01"));
        AddPacket(new NetworkPacket(6, "192.168.10.15", "8.8.8.8", 2500, 53, "UDP", "DNSQUERY"));
        AddPacket(new NetworkPacket(7, "192.168.10.15", "1.1.1.1", 2501, 443, "TCP", "WEBREQUEST"));
        AddPacket(new NetworkPacket(8, "203.0.113.10", "198.51.100.20", 1111, 2222, "GRE", "UNKNOWNPROTOCOL"));
    }

    private void AddLog(string message)
    {
        if (!LoggingEnabled) return;
        _logs.Add($"[{DateTime.Now:HH:mm:ss}] {message}");
    }
}
