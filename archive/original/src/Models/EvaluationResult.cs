namespace FirewallTutor.Models;

public sealed class EvaluationResult
{
    public NetworkPacket Packet { get; }
    public RuleAction FinalAction { get; }
    public int MatchedRuleId { get; }
    public string Reason { get; }

    public EvaluationResult(NetworkPacket packet, RuleAction finalAction, int matchedRuleId, string reason)
    {
        Packet = packet;
        FinalAction = finalAction;
        MatchedRuleId = matchedRuleId;
        Reason = reason;
    }
}
