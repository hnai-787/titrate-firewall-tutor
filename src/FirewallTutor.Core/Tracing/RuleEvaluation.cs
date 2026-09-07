using FirewallTutor.Core.Model;

namespace FirewallTutor.Core.Tracing;

public sealed record RuleEvaluation(
    FirewallRule Rule,
    IReadOnlyList<FieldEvaluation> Fields,
    bool Matched,
    bool EvaluationStoppedHere)
{
    /// <summary>The first field (in evaluation order) that failed, or null if every field matched.</summary>
    public FieldEvaluation? FirstFailure => Fields.FirstOrDefault(f => !f.Matched);
}
