namespace FirewallTutor.Core.Model;

public sealed class Policy
{
    public IReadOnlyList<FirewallRule> Rules { get; init; } = Array.Empty<FirewallRule>();
    public RuleAction DefaultAction { get; init; } = RuleAction.Deny;
}
