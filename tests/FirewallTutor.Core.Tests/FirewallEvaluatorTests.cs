using FirewallTutor.Core.Evaluation;
using FirewallTutor.Core.Model;

namespace FirewallTutor.Core.Tests;

public class FirewallEvaluatorTests
{
    private static uint Ip(string s) => AddressSpec.TryParseIp(s, out uint v) ? v : throw new Exception("bad ip");

    private static FirewallRule Rule(int ordinal, RuleAction action, string protocol = "tcp",
        AddressSpec? src = null, PortSpec? srcPort = null, AddressSpec? dst = null, PortSpec? dstPort = null) => new()
    {
        Ordinal = ordinal,
        SourceLine = ordinal,
        Action = action,
        Protocol = ProtocolSpec.Named(protocol),
        Source = src ?? AddressSpec.Any(),
        SourcePort = srcPort ?? PortSpec.Any(),
        Destination = dst ?? AddressSpec.Any(),
        DestinationPort = dstPort ?? PortSpec.Any(),
    };

    private static Packet Packet(string protocol = "tcp", string src = "10.0.0.5", int srcPort = 5000,
        string dst = "192.168.1.10", int dstPort = 443) => new()
    {
        Protocol = protocol,
        SourceAddress = Ip(src),
        SourcePort = srcPort,
        DestinationAddress = Ip(dst),
        DestinationPort = dstPort,
    };

    [Fact]
    public void First_rule_match_stops_evaluation_immediately()
    {
        var policy = new Policy { Rules = [Rule(1, RuleAction.Allow), Rule(2, RuleAction.Deny)] };
        var trace = FirewallEvaluator.Evaluate(policy, Packet());

        Assert.Equal(RuleAction.Allow, trace.FinalAction);
        Assert.Equal(1, trace.MatchedRuleOrdinal);
        Assert.False(trace.UsedImplicitDefault);
        Assert.True(trace.Steps[0].EvaluationStoppedHere);
        Assert.False(trace.Steps[1].EvaluationStoppedHere);
        Assert.Empty(trace.Steps[1].Fields); // rule 2 never actually ran
    }

    [Fact]
    public void Middle_rule_match_leaves_earlier_rules_evaluated_and_later_ones_untouched()
    {
        var policy = new Policy
        {
            Rules =
            [
                Rule(1, RuleAction.Deny, dst: AddressSpec.Host(Ip("1.2.3.4"))), // won't match
                Rule(2, RuleAction.Allow),                                       // matches
                Rule(3, RuleAction.Deny),                                        // never runs
            ]
        };
        var trace = FirewallEvaluator.Evaluate(policy, Packet());

        Assert.Equal(2, trace.MatchedRuleOrdinal);
        Assert.NotEmpty(trace.Steps[0].Fields);   // rule 1 was actually checked
        Assert.False(trace.Steps[0].Matched);
        Assert.True(trace.Steps[1].Matched);
        Assert.Empty(trace.Steps[2].Fields);      // rule 3 never ran
    }

    [Fact]
    public void No_match_falls_through_to_the_implicit_default()
    {
        var policy = new Policy
        {
            DefaultAction = RuleAction.Deny,
            Rules = [Rule(1, RuleAction.Allow, dst: AddressSpec.Host(Ip("1.2.3.4")))],
        };
        var trace = FirewallEvaluator.Evaluate(policy, Packet());

        Assert.Null(trace.MatchedRuleOrdinal);
        Assert.True(trace.UsedImplicitDefault);
        Assert.Equal(RuleAction.Deny, trace.FinalAction);
    }

    [Fact]
    public void Protocol_mismatch_is_reported_with_a_clear_explanation()
    {
        var policy = new Policy { Rules = [Rule(1, RuleAction.Allow, protocol: "udp")] };
        var trace = FirewallEvaluator.Evaluate(policy, Packet(protocol: "tcp"));

        var protocolField = trace.Steps[0].Fields.Single(f => f.FieldName == "Protocol");
        Assert.False(protocolField.Matched);
        Assert.Contains("TCP", protocolField.Explanation);
        Assert.Contains("udp", protocolField.Explanation);
        Assert.True(trace.UsedImplicitDefault);
    }

    [Fact]
    public void Source_address_mismatch_is_reported()
    {
        var rule = Rule(1, RuleAction.Allow, src: AddressSpec.Cidr(Ip("172.16.0.0"), 16));
        var trace = FirewallEvaluator.Evaluate(new Policy { Rules = [rule] }, Packet(src: "10.0.0.5"));

        var field = trace.Steps[0].Fields.Single(f => f.FieldName == "Source");
        Assert.False(field.Matched);
    }

    [Fact]
    public void Destination_address_mismatch_is_reported()
    {
        var rule = Rule(1, RuleAction.Allow, dst: AddressSpec.Host(Ip("192.168.1.99")));
        var trace = FirewallEvaluator.Evaluate(new Policy { Rules = [rule] }, Packet(dst: "192.168.1.10"));

        var field = trace.Steps[0].Fields.Single(f => f.FieldName == "Destination");
        Assert.False(field.Matched);
    }

    [Fact]
    public void Source_port_mismatch_is_reported_for_port_capable_protocols()
    {
        var rule = Rule(1, RuleAction.Allow, srcPort: PortSpec.Eq(22));
        var trace = FirewallEvaluator.Evaluate(new Policy { Rules = [rule] }, Packet(srcPort: 5000));

        var field = trace.Steps[0].Fields.Single(f => f.FieldName == "Source port");
        Assert.False(field.Matched);
    }

    [Fact]
    public void Destination_port_mismatch_is_reported_for_port_capable_protocols()
    {
        var rule = Rule(1, RuleAction.Allow, dstPort: PortSpec.Eq(80));
        var trace = FirewallEvaluator.Evaluate(new Policy { Rules = [rule] }, Packet(dstPort: 443));

        var field = trace.Steps[0].Fields.Single(f => f.FieldName == "Destination port");
        Assert.False(field.Matched);
    }

    [Fact]
    public void Port_fields_are_not_evaluated_for_non_port_capable_protocols_like_icmp()
    {
        var rule = Rule(1, RuleAction.Allow, protocol: "icmp");
        var trace = FirewallEvaluator.Evaluate(new Policy { Rules = [rule] }, Packet(protocol: "icmp"));

        Assert.DoesNotContain(trace.Steps[0].Fields, f => f.FieldName.Contains("port"));
    }

    [Fact]
    public void Multiple_mismatches_are_all_reported_not_just_the_first()
    {
        var rule = Rule(1, RuleAction.Allow, protocol: "udp", dst: AddressSpec.Host(Ip("1.2.3.4")));
        var trace = FirewallEvaluator.Evaluate(new Policy { Rules = [rule] }, Packet(protocol: "tcp", dst: "192.168.1.10"));

        Assert.False(trace.Steps[0].Fields.Single(f => f.FieldName == "Protocol").Matched);
        Assert.False(trace.Steps[0].Fields.Single(f => f.FieldName == "Destination").Matched);
    }

    [Fact]
    public void Broad_rule_before_specific_rule_shadows_the_specific_rule()
    {
        var policy = new Policy
        {
            Rules =
            [
                Rule(1, RuleAction.Allow, dst: AddressSpec.Cidr(Ip("192.168.1.0"), 24)),
                Rule(2, RuleAction.Deny, dst: AddressSpec.Host(Ip("192.168.1.10"))),
            ]
        };
        var trace = FirewallEvaluator.Evaluate(policy, Packet(dst: "192.168.1.10"));

        Assert.Equal(RuleAction.Allow, trace.FinalAction); // the narrow deny never gets a chance
        Assert.Equal(1, trace.MatchedRuleOrdinal);
    }

    [Fact]
    public void Specific_rule_before_broad_rule_lets_the_exception_win()
    {
        var policy = new Policy
        {
            Rules =
            [
                Rule(1, RuleAction.Deny, dst: AddressSpec.Host(Ip("192.168.1.10"))),
                Rule(2, RuleAction.Allow, dst: AddressSpec.Cidr(Ip("192.168.1.0"), 24)),
            ]
        };
        var trace = FirewallEvaluator.Evaluate(policy, Packet(dst: "192.168.1.10"));

        Assert.Equal(RuleAction.Deny, trace.FinalAction); // same two rules, opposite order -> opposite result
        Assert.Equal(1, trace.MatchedRuleOrdinal);
    }
}
