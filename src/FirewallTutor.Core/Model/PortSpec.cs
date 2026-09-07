namespace FirewallTutor.Core.Model;

public enum PortOperator
{
    Any,
    Eq,
    Range,
    Gt,
    Lt,
    Neq
}

public sealed class PortSpec
{
    public PortOperator Operator { get; }
    public int Value { get; }
    public int RangeEnd { get; }

    private PortSpec(PortOperator op, int value, int rangeEnd)
    {
        Operator = op;
        Value = value;
        RangeEnd = rangeEnd;
    }

    public static PortSpec Any() => new(PortOperator.Any, 0, 0);
    public static PortSpec Eq(int port) => new(PortOperator.Eq, port, port);
    public static PortSpec Range(int start, int end) => new(PortOperator.Range, start, end);
    public static PortSpec Gt(int port) => new(PortOperator.Gt, port, 65535);
    public static PortSpec Lt(int port) => new(PortOperator.Lt, 0, port);
    public static PortSpec Neq(int port) => new(PortOperator.Neq, port, port);

    public bool Matches(int port) => Operator switch
    {
        PortOperator.Any => true,
        PortOperator.Eq => port == Value,
        PortOperator.Range => port >= Value && port <= RangeEnd,
        PortOperator.Gt => port > Value,
        PortOperator.Lt => port < RangeEnd,
        PortOperator.Neq => port != Value,
        _ => false
    };

    public override string ToString() => Operator switch
    {
        PortOperator.Any => "any",
        PortOperator.Eq => $"eq {Value}",
        PortOperator.Range => $"range {Value} {RangeEnd}",
        PortOperator.Gt => $"gt {Value}",
        PortOperator.Lt => $"lt {RangeEnd}",
        PortOperator.Neq => $"neq {Value}",
        _ => "?"
    };
}
