using FirewallTutor.Core.Evaluation;
using FirewallTutor.Core.Model;
using FirewallTutor.Core.Parsing;
using Spectre.Console;

if (args.Length == 0 || args[0] is "--help" or "-h")
{
    PrintHelp();
    return args.Length == 0 ? 2 : 0;
}

string? file = null;
string protocol = "tcp", src = "", dst = "";
int srcPort = 0, dstPort = 0;
bool auto = false;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--file": file = args[++i]; break;
        case "--protocol": protocol = args[++i]; break;
        case "--src": src = args[++i]; break;
        case "--dst": dst = args[++i]; break;
        case "--src-port": srcPort = int.Parse(args[++i]); break;
        case "--dst-port": dstPort = int.Parse(args[++i]); break;
        case "--auto": auto = true; break;
        default:
            AnsiConsole.MarkupLine($"[red]Unrecognized option: {args[i]}[/]");
            return 2;
    }
}

if (file is null || src.Length == 0 || dst.Length == 0)
{
    AnsiConsole.MarkupLine("[red]Error:[/] --file, --src, and --dst are required.");
    PrintHelp();
    return 2;
}

string source = File.ReadAllText(file);
ParseResult parsed = CiscoAclParser.Parse(source);

if (!parsed.Ok)
{
    AnsiConsole.MarkupLine("[red]Error: policy could not be parsed -- refusing to guess.[/]");
    foreach (var error in parsed.Errors)
    {
        AnsiConsole.MarkupLine($"  line {error.Line}: {error.Message.EscapeMarkup()}");
    }
    return 2;
}

if (!AddressSpec.TryParseIp(src, out uint srcIp) || !AddressSpec.TryParseIp(dst, out uint dstIp))
{
    AnsiConsole.MarkupLine("[red]Error: --src/--dst must be valid IPv4 addresses.[/]");
    return 2;
}

var packet = new Packet { Protocol = protocol, SourceAddress = srcIp, SourcePort = srcPort, DestinationAddress = dstIp, DestinationPort = dstPort };
var trace = FirewallEvaluator.Evaluate(parsed.Policy, packet);

AnsiConsole.Write(new Rule("[bold]Firewall Tutor[/] -- step-through evaluation").LeftJustified());
AnsiConsole.MarkupLine($"Packet: [yellow]{packet.DisplayText.EscapeMarkup()}[/]");
AnsiConsole.WriteLine();

if (!auto)
{
    string guess = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("Before we step through it: what do you think the firewall will do?")
            .AddChoices("allow", "deny", "not sure"));
    AnsiConsole.MarkupLine($"You predicted: [italic]{guess}[/]. Let's find out.");
    AnsiConsole.WriteLine();
}

foreach (var step in trace.Steps)
{
    var header = new Rule($"Rule {step.Rule.Ordinal} (line {step.Rule.SourceLine}): {step.Rule.Action} {step.Rule.RawText.EscapeMarkup()}").LeftJustified();
    AnsiConsole.Write(header);

    if (step.Fields.Count == 0)
    {
        AnsiConsole.MarkupLine("[grey]NOT EVALUATED -- an earlier rule already matched and evaluation stopped there.[/]");
    }
    else
    {
        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Field");
        table.AddColumn("Packet value");
        table.AddColumn("Rule value");
        table.AddColumn("Result");

        foreach (var field in step.Fields)
        {
            string mark = field.Matched ? "[green]OK[/]" : "[red]FAIL[/]";
            table.AddRow(field.FieldName, field.PacketValue.EscapeMarkup(), field.RuleValue.EscapeMarkup(), mark);
        }
        AnsiConsole.Write(table);

        if (step.Matched)
        {
            AnsiConsole.MarkupLine($"[bold green]MATCH -- {step.Rule.Action.ToString().ToUpperInvariant()}[/]");
            AnsiConsole.MarkupLine("[bold]---- EVALUATION STOPS HERE (first match wins) ----[/]");
        }
        else
        {
            var failure = step.FirstFailure!;
            AnsiConsole.MarkupLine($"[red]NO MATCH[/] -- {failure.FieldName}: {failure.Explanation.EscapeMarkup()}. Continuing to the next rule.");
        }
    }

    AnsiConsole.WriteLine();
    if (!auto && step != trace.Steps[^1])
    {
        AnsiConsole.Markup("[grey](press Enter for next rule)[/]");
        Console.ReadLine();
    }
}

var implicitStyle = trace.UsedImplicitDefault ? "bold yellow" : "grey";
AnsiConsole.MarkupLine($"[{implicitStyle}]Implicit default: deny ip any any (always present, applies only if nothing above matched)[/]");
if (trace.UsedImplicitDefault)
{
    AnsiConsole.MarkupLine("[bold]No configured rule matched -- the implicit default action determined the result.[/]");
}

AnsiConsole.WriteLine();
AnsiConsole.Write(new Rule("Summary").LeftJustified());
AnsiConsole.MarkupLine($"Final decision: [bold]{trace.FinalAction.ToString().ToUpperInvariant()}[/]");
AnsiConsole.MarkupLine(trace.MatchedRuleOrdinal is int ord
    ? $"Matched rule: {ord} (line {trace.Steps.First(s => s.Rule.Ordinal == ord).Rule.SourceLine})"
    : "Matched rule: none -- implicit default");
AnsiConsole.MarkupLine($"Rules evaluated before a decision: {trace.Steps.Count(s => s.Fields.Count > 0)} of {trace.Steps.Count}");

return 0;

static void PrintHelp()
{
    AnsiConsole.MarkupLine("[bold]FirewallTutor.Cli[/] -- step through ACL evaluation for one packet");
    AnsiConsole.MarkupLine("");
    AnsiConsole.MarkupLine("Usage:");
    AnsiConsole.MarkupLine("  fwtutor --file <acl-file> --protocol <tcp|udp|icmp> --src <ip> --dst <ip>");
    AnsiConsole.MarkupLine("          [--src-port <n>] [--dst-port <n>] [--auto]");
    AnsiConsole.MarkupLine("");
    AnsiConsole.MarkupLine("  --auto   run straight through without waiting for Enter between rules");
}
