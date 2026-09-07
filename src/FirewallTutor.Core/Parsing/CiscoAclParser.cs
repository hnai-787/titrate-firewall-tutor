using FirewallTutor.Core.Model;

namespace FirewallTutor.Core.Parsing;

/// <summary>
/// Parses a bounded subset of Cisco IOS/IOS XE extended IPv4 ACL syntax --
/// the same educational subset fwlint's C++ parser supports, reimplemented
/// here rather than shared, since the two tools serve different purposes
/// (auditing a whole policy vs. explaining one packet's path through it).
/// Fails closed on anything outside the subset: a tutor that silently
/// mis-parses a rule and then "explains" the wrong thing is worse than one
/// that refuses to run. See README "Design decisions".
/// </summary>
public static class CiscoAclParser
{
    private static readonly Dictionary<string, int> NamedPorts = new()
    {
        ["telnet"] = 23, ["www"] = 80, ["http"] = 80, ["https"] = 443,
        ["ftp"] = 21, ["ssh"] = 22, ["smtp"] = 25, ["domain"] = 53, ["dns"] = 53,
    };

    public static ParseResult Parse(string source)
    {
        var errors = new List<ParseError>();
        var rules = new List<FirewallRule>();
        string? currentAclName = null;
        int lineNumber = 0;
        int ordinal = 0;

        foreach (string rawLine in source.Replace("\r\n", "\n").Split('\n'))
        {
            lineNumber++;
            string line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('!')) continue;

            string[] tokens = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length == 0) continue;

            if (tokens is ["ip", "access-list", "extended", ..] && tokens.Length >= 4)
            {
                currentAclName = tokens[3];
                continue;
            }

            int idx;
            if (tokens[0] == "access-list")
            {
                if (tokens.Length < 3)
                {
                    errors.Add(new ParseError(lineNumber, $"malformed access-list line: \"{line}\""));
                    return Fail(errors);
                }
                idx = 2;
            }
            else if (tokens[0] is "permit" or "deny")
            {
                idx = 0;
            }
            else if (currentAclName is not null && int.TryParse(tokens[0], out _))
            {
                idx = 1;
            }
            else
            {
                errors.Add(new ParseError(lineNumber, $"unsupported or unrecognized ACL syntax: \"{line}\""));
                return Fail(errors);
            }

            if (idx >= tokens.Length || tokens[idx] is not ("permit" or "deny"))
            {
                errors.Add(new ParseError(lineNumber, $"expected \"permit\" or \"deny\" in: \"{line}\""));
                return Fail(errors);
            }
            RuleAction action = tokens[idx] == "permit" ? RuleAction.Allow : RuleAction.Deny;
            idx++;

            if (idx >= tokens.Length)
            {
                errors.Add(new ParseError(lineNumber, $"missing protocol in: \"{line}\""));
                return Fail(errors);
            }
            string protocolToken = tokens[idx].ToLowerInvariant();
            ProtocolSpec protocol;
            try { protocol = ProtocolSpec.Named(protocolToken); }
            catch (FormatException)
            {
                errors.Add(new ParseError(lineNumber, $"unsupported protocol \"{tokens[idx]}\""));
                return Fail(errors);
            }
            idx++;
            bool portCapable = ProtocolSpec.IsPortCapable(protocolToken);

            if (!TryParseAddress(tokens, ref idx, out AddressSpec? sourceAddress))
            {
                errors.Add(new ParseError(lineNumber, $"malformed source address in: \"{line}\""));
                return Fail(errors);
            }

            PortSpec sourcePort = PortSpec.Any();
            if (portCapable && !TryParsePortClause(tokens, ref idx, out sourcePort!))
            {
                errors.Add(new ParseError(lineNumber, $"malformed source port clause in: \"{line}\""));
                return Fail(errors);
            }

            if (!TryParseAddress(tokens, ref idx, out AddressSpec? destination))
            {
                errors.Add(new ParseError(lineNumber, $"malformed destination address in: \"{line}\""));
                return Fail(errors);
            }

            PortSpec destinationPort = PortSpec.Any();
            if (portCapable && !TryParsePortClause(tokens, ref idx, out destinationPort!))
            {
                errors.Add(new ParseError(lineNumber, $"malformed destination port clause in: \"{line}\""));
                return Fail(errors);
            }

            if (idx < tokens.Length && tokens[idx] == "log") idx++;

            if (idx != tokens.Length)
            {
                errors.Add(new ParseError(lineNumber,
                    $"unsupported trailing syntax (e.g. established/precedence/tos/time-range) in: \"{line}\""));
                return Fail(errors);
            }

            ordinal++;
            rules.Add(new FirewallRule
            {
                Ordinal = ordinal,
                SourceLine = lineNumber,
                Action = action,
                Protocol = protocol,
                Source = sourceAddress!,
                SourcePort = sourcePort,
                Destination = destination!,
                DestinationPort = destinationPort,
                RawText = line,
            });
        }

        if (rules.Count == 0 && errors.Count == 0)
        {
            errors.Add(new ParseError(0, "no ACL rules found in input"));
            return Fail(errors);
        }

        return new ParseResult { Ok = true, Policy = new Policy { Rules = rules, DefaultAction = RuleAction.Deny } };
    }

    private static ParseResult Fail(List<ParseError> errors) => new() { Ok = false, Errors = errors };

    private static bool TryParseAddress(string[] tokens, ref int idx, out AddressSpec? spec)
    {
        spec = null;
        if (idx >= tokens.Length) return false;

        if (tokens[idx] == "any")
        {
            idx++;
            spec = AddressSpec.Any();
            return true;
        }
        if (tokens[idx] == "host")
        {
            idx++;
            if (idx >= tokens.Length || !AddressSpec.TryParseIp(tokens[idx], out uint host)) return false;
            idx++;
            spec = AddressSpec.Host(host);
            return true;
        }
        if (idx + 1 >= tokens.Length) return false;
        if (!AddressSpec.TryParseIp(tokens[idx], out uint baseAddr)) return false;
        if (!AddressSpec.TryParseIp(tokens[idx + 1], out uint wildcard)) return false;
        idx += 2;
        spec = AddressSpec.WildcardMask(baseAddr, wildcard);
        return true;
    }

    private static bool TryParsePortClause(string[] tokens, ref int idx, out PortSpec? spec)
    {
        spec = PortSpec.Any();
        if (idx >= tokens.Length || tokens[idx] is not ("eq" or "range" or "gt" or "lt" or "neq"))
        {
            return true; // no port clause present -> "any"
        }
        string op = tokens[idx++];

        if (op == "range")
        {
            if (idx + 1 >= tokens.Length) { spec = null; return false; }
            if (!TryParsePort(tokens[idx++], out int lo) || !TryParsePort(tokens[idx++], out int hi) || lo > hi)
            {
                spec = null;
                return false;
            }
            spec = PortSpec.Range(lo, hi);
            return true;
        }

        if (idx >= tokens.Length || !TryParsePort(tokens[idx++], out int value))
        {
            spec = null;
            return false;
        }

        spec = op switch
        {
            "eq" => PortSpec.Eq(value),
            "gt" => PortSpec.Gt(value),
            "lt" => PortSpec.Lt(value),
            "neq" => PortSpec.Neq(value),
            _ => null,
        };
        return spec is not null;
    }

    private static bool TryParsePort(string token, out int port)
    {
        if (NamedPorts.TryGetValue(token.ToLowerInvariant(), out port)) return true;
        return int.TryParse(token, out port) && port is >= 0 and <= 65535;
    }
}
