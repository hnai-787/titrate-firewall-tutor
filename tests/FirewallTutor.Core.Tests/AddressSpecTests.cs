using FirewallTutor.Core.Model;

namespace FirewallTutor.Core.Tests;

public class AddressSpecTests
{
    private static uint Ip(string s) => AddressSpec.TryParseIp(s, out uint v) ? v : throw new Exception("bad ip");

    [Fact]
    public void Any_matches_everything()
    {
        Assert.True(AddressSpec.Any().Matches(Ip("1.2.3.4")));
        Assert.True(AddressSpec.Any().Matches(Ip("255.255.255.255")));
    }

    [Fact]
    public void Host_matches_only_exact_address()
    {
        var spec = AddressSpec.Host(Ip("10.0.0.5"));
        Assert.True(spec.Matches(Ip("10.0.0.5")));
        Assert.False(spec.Matches(Ip("10.0.0.6")));
    }

    [Fact]
    public void Wildcard_equivalent_to_slash24_matches_whole_subnet()
    {
        var spec = AddressSpec.WildcardMask(Ip("192.168.1.0"), Ip("0.0.0.255"));
        Assert.True(spec.Matches(Ip("192.168.1.0")));
        Assert.True(spec.Matches(Ip("192.168.1.255")));
        Assert.False(spec.Matches(Ip("192.168.2.1")));
    }

    [Fact]
    public void Cidr_matches_the_same_way_as_the_equivalent_wildcard()
    {
        var cidr = AddressSpec.Cidr(Ip("10.0.0.0"), 24);
        Assert.True(cidr.Matches(Ip("10.0.0.200")));
        Assert.False(cidr.Matches(Ip("10.0.1.0")));
    }

    [Fact]
    public void Discontiguous_wildcard_is_supported_for_single_packet_membership_testing()
    {
        // Unlike fwlint (which needs exact set algebra across a whole
        // policy and therefore rejects discontiguous masks), the tutor
        // only ever tests one concrete packet at a time, so a
        // discontiguous wildcard like 0.0.255.0 ("ignore the third octet
        // only") is perfectly well-defined here.
        var spec = AddressSpec.WildcardMask(Ip("10.1.0.5"), Ip("0.0.255.0"));
        Assert.True(spec.Matches(Ip("10.1.99.5")));   // third octet ignored
        Assert.False(spec.Matches(Ip("10.1.99.6")));  // last octet must still match
        Assert.False(spec.Matches(Ip("10.2.0.5")));   // second octet must still match
    }

    [Fact]
    public void Explain_reports_which_direction_the_match_went()
    {
        var spec = AddressSpec.Cidr(Ip("10.0.0.0"), 24);
        Assert.Contains("matches", spec.Explain(Ip("10.0.0.1")));
        Assert.Contains("does not match", spec.Explain(Ip("10.0.1.1")));
    }
}
