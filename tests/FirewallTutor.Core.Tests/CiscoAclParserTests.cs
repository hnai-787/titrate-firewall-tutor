using FirewallTutor.Core.Evaluation;
using FirewallTutor.Core.Model;
using FirewallTutor.Core.Parsing;

namespace FirewallTutor.Core.Tests;

public class CiscoAclParserTests
{
    private static uint Ip(string s) => AddressSpec.TryParseIp(s, out uint v) ? v : throw new Exception("bad ip");

    [Fact]
    public void Parses_a_numbered_access_list()
    {
        string src = "access-list 110 permit tcp 10.0.0.0 0.0.0.255 host 192.0.2.10 eq 443\n" +
                     "access-list 110 deny tcp any any\n";
        var result = CiscoAclParser.Parse(src);

        Assert.True(result.Ok);
        Assert.Equal(2, result.Policy.Rules.Count);
        Assert.Equal(RuleAction.Allow, result.Policy.Rules[0].Action);
    }

    [Fact]
    public void Parses_a_named_extended_acl_with_sequence_numbers_and_named_ports()
    {
        string src = "ip access-list extended EDGE-IN\n" +
                     " 10 permit tcp 10.0.0.0 0.0.0.255 any eq telnet\n" +
                     " 20 deny ip any any\n";
        var result = CiscoAclParser.Parse(src);

        Assert.True(result.Ok);
        Assert.Equal(2, result.Policy.Rules.Count);
        Assert.True(result.Policy.Rules[0].DestinationPort.Matches(23));
    }

    [Fact]
    public void Comment_and_blank_lines_are_ignored()
    {
        string src = "! comment\n\naccess-list 100 permit ip any any\n";
        var result = CiscoAclParser.Parse(src);
        Assert.True(result.Ok);
        Assert.Single(result.Policy.Rules);
    }

    [Fact]
    public void Range_and_gt_lt_neq_operators_parse_correctly()
    {
        string src = "access-list 100 permit tcp any any range 8000 8999\n" +
                     "access-list 100 permit tcp any eq 22 any\n" +
                     "access-list 100 permit tcp any any neq 80\n";
        var result = CiscoAclParser.Parse(src);

        Assert.True(result.Ok);
        Assert.True(result.Policy.Rules[0].DestinationPort.Matches(8500));
        Assert.False(result.Policy.Rules[0].DestinationPort.Matches(7999));
        Assert.True(result.Policy.Rules[1].SourcePort.Matches(22));
        Assert.False(result.Policy.Rules[2].DestinationPort.Matches(80));
    }

    [Fact]
    public void Unsupported_trailing_keyword_fails_closed()
    {
        var result = CiscoAclParser.Parse("access-list 100 permit tcp any any established\n");
        Assert.False(result.Ok);
        Assert.NotEmpty(result.Errors);
        Assert.Equal(1, result.Errors[0].Line);
    }

    [Fact]
    public void Missing_permit_or_deny_fails_closed_with_a_line_number()
    {
        var result = CiscoAclParser.Parse("access-list 100 allow tcp any any\n");
        Assert.False(result.Ok);
        Assert.Equal(1, result.Errors[0].Line);
    }

    [Fact]
    public void Unknown_protocol_fails_closed()
    {
        var result = CiscoAclParser.Parse("access-list 100 permit sctp any any\n");
        Assert.False(result.Ok);
    }

    [Fact]
    public void Parsed_policy_round_trips_through_the_evaluator()
    {
        string src = "access-list 100 permit tcp 10.0.0.0 0.0.0.255 any eq 443\n" +
                     "access-list 100 deny ip any any\n";
        var parsed = CiscoAclParser.Parse(src);
        Assert.True(parsed.Ok);

        var packet = new Packet { Protocol = "tcp", SourceAddress = Ip("10.0.0.5"), SourcePort = 5000, DestinationAddress = Ip("8.8.8.8"), DestinationPort = 443 };
        var trace = FirewallEvaluator.Evaluate(parsed.Policy, packet);

        Assert.Equal(RuleAction.Allow, trace.FinalAction);
        Assert.Equal(1, trace.MatchedRuleOrdinal);
    }
}
