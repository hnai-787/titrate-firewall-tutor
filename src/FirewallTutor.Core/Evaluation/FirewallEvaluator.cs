using FirewallTutor.Core.Model;
using FirewallTutor.Core.Tracing;

namespace FirewallTutor.Core.Evaluation;

/// <summary>
/// Evaluates one concrete packet against a policy and returns the full
/// execution trace -- every rule considered, every field checked, and why
/// each one did or didn't match -- rather than just the final decision.
/// The trace *is* the product: a tutoring UI renders it directly instead
/// of re-deriving explanations itself, so the UI and the evaluator can
/// never disagree about why something happened.
/// </summary>
public static class FirewallEvaluator
{
    public static EvaluationTrace Evaluate(Policy policy, Packet packet)
    {
        var steps = new List<RuleEvaluation>();
        int? matchedOrdinal = null;
        RuleAction finalAction = policy.DefaultAction;
        bool usedDefault = true;

        foreach (FirewallRule rule in policy.Rules)
        {
            if (matchedOrdinal is not null)
            {
                // Evaluation already stopped at an earlier rule -- this
                // rule never actually ran in the real firewall, so its
                // fields are never computed (not "computed and hidden";
                // genuinely not evaluated), matching first-match-wins
                // semantics exactly.
                steps.Add(new RuleEvaluation(rule, Array.Empty<FieldEvaluation>(), Matched: false, EvaluationStoppedHere: false));
                continue;
            }

            var fields = new List<FieldEvaluation> { EvaluateProtocol(rule, packet), EvaluateAddress("Source", rule.Source, packet.SourceAddress) };
            if (rule.IsPortCapable) fields.Add(EvaluatePort("Source port", rule.SourcePort, packet.SourcePort));
            fields.Add(EvaluateAddress("Destination", rule.Destination, packet.DestinationAddress));
            if (rule.IsPortCapable) fields.Add(EvaluatePort("Destination port", rule.DestinationPort, packet.DestinationPort));

            bool matched = fields.All(f => f.Matched);
            if (matched)
            {
                matchedOrdinal = rule.Ordinal;
                finalAction = rule.Action;
                usedDefault = false;
            }
            steps.Add(new RuleEvaluation(rule, fields, matched, EvaluationStoppedHere: matched));
        }

        return new EvaluationTrace(packet, steps, finalAction, matchedOrdinal, usedDefault);
    }

    private static FieldEvaluation EvaluateProtocol(FirewallRule rule, Packet packet)
    {
        bool matched = rule.Protocol.Matches(packet.ProtocolNumber);
        string explanation = rule.Protocol.IsAny
            ? "any protocol matches"
            : matched
                ? $"{packet.Protocol.ToUpperInvariant()} satisfies {rule.Protocol}"
                : $"{packet.Protocol.ToUpperInvariant()} does not satisfy {rule.Protocol}";
        return new FieldEvaluation("Protocol", packet.Protocol.ToUpperInvariant(), rule.Protocol.ToString(), matched, explanation);
    }

    private static FieldEvaluation EvaluateAddress(string name, AddressSpec spec, uint address)
    {
        bool matched = spec.Matches(address);
        string? bits = spec.Wildcard != 0 && !spec.IsAny ? spec.BitBreakdown(address) : null;
        return new FieldEvaluation(name, AddressSpec.FormatIp(address), spec.ToString(), matched, spec.Explain(address), bits);
    }

    private static FieldEvaluation EvaluatePort(string name, PortSpec spec, int port)
    {
        bool matched = spec.Matches(port);
        string explanation = matched
            ? $"{port} satisfies {spec}"
            : $"{port} does not satisfy {spec}";
        return new FieldEvaluation(name, port.ToString(), spec.ToString(), matched, explanation);
    }
}
