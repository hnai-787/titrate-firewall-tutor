using FirewallTutor.Core.Model;

namespace FirewallTutor.Core.Tracing;

public sealed record EvaluationTrace(
    Packet Packet,
    IReadOnlyList<RuleEvaluation> Steps,
    RuleAction FinalAction,
    int? MatchedRuleOrdinal,
    bool UsedImplicitDefault);
