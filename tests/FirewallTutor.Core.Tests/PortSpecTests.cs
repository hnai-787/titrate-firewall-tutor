using FirewallTutor.Core.Model;

namespace FirewallTutor.Core.Tests;

public class PortSpecTests
{
    [Fact]
    public void Any_matches_every_port() => Assert.True(PortSpec.Any().Matches(0) && PortSpec.Any().Matches(65535));

    [Fact]
    public void Eq_matches_only_that_port()
    {
        var spec = PortSpec.Eq(443);
        Assert.True(spec.Matches(443));
        Assert.False(spec.Matches(80));
    }

    [Fact]
    public void Range_is_inclusive_on_both_ends()
    {
        var spec = PortSpec.Range(8000, 8100);
        Assert.True(spec.Matches(8000));
        Assert.True(spec.Matches(8100));
        Assert.False(spec.Matches(7999));
        Assert.False(spec.Matches(8101));
    }

    [Theory]
    [InlineData(1024, 1023, false)]
    [InlineData(1024, 1024, false)]
    [InlineData(1024, 1025, true)]
    public void Gt_is_strictly_greater_than(int threshold, int port, bool expected) =>
        Assert.Equal(expected, PortSpec.Gt(threshold).Matches(port));

    [Fact]
    public void Neq_excludes_only_the_named_port()
    {
        var spec = PortSpec.Neq(80);
        Assert.False(spec.Matches(80));
        Assert.True(spec.Matches(81));
    }
}
