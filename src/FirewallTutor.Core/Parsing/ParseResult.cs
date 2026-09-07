using FirewallTutor.Core.Model;

namespace FirewallTutor.Core.Parsing;

public sealed class ParseResult
{
    public bool Ok { get; init; }
    public Policy Policy { get; init; } = new();
    public IReadOnlyList<ParseError> Errors { get; init; } = Array.Empty<ParseError>();
}
