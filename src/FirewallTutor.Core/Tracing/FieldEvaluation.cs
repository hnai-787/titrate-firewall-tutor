namespace FirewallTutor.Core.Tracing;

public sealed record FieldEvaluation(
    string FieldName,
    string PacketValue,
    string RuleValue,
    bool Matched,
    string Explanation,
    string? BitBreakdown = null);
