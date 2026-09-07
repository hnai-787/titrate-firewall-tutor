# Firewall Tutor (C#)

## Course Information

| Field | Details |
|---|---|
| Course | Object-Oriented Programming (CS112) |
| Semester | Semester 2 — Spring 2024 |
| University | Air University, Islamabad |
| Students | Hussain Ali (232095), Syed Jazib Ali Rizvi (232145), Shehroze Sameer (232091) |

## Overview

A Windows Forms "Firewall Tutor" app that teaches how a rule-based firewall
evaluates packets, by walking through Rules, Packets, Firewall evaluation,
and Logs in a tabbed interface.

## Problem Statement

Make firewall rule evaluation visible and interactive for someone learning
the concept, rather than a black box — show the ordered rules, the packets,
and the step-by-step decision for each one.

## Objectives

- Model a `FirewallEngine` that evaluates packets against an ordered rule
  list with a configurable default action.
- Persist rules/packets/results via CSV so state survives between runs.
- Present the whole flow through a guided tabbed UI (including a Tutorial tab).

## Tools and Technologies

- C# / .NET (WinForms)
- CSV-based persistence (`Services/CsvStorage.cs`)

## Features

- Tabs: Home, Rules, Packets, Firewall, Settings, Tutorial, About.
- Ordered rule evaluation with a configurable default action (default DENY).
- Log of evaluation results per packet.

## Methodology

1. Design the `FirewallEngine` evaluation logic (protocol/IP/field-agnostic string matching).
2. Build the WinForms UI around it (`src/Forms`, `src/Models`, `src/Services`).
3. Mirror the same rules/packets dataset used in the C++ version
   ([`firewall-rule-engine-cpp`](../firewall-rule-engine-cpp/)) for direct comparison.
4. Verify output against expected decisions.

## Repository Structure

```text
firewall-tutor-csharp/
  README.md
  PROJECT_NOTES.md
  src/               (Forms/, Models/, Services/, Program.cs)
  data/              (rules.csv, packets.csv)
  output/            (results.csv)
  docs/              (original report)
  screenshots/
  project.yaml
```

## Setup Instructions

```bash
dotnet build
```

## Usage

```bash
dotnet run
# or open FirewallTutor.csproj in Visual Studio and run
```

## How to Review

1. Start with this README.
2. Open `docs/firewall-tutor-csharp.docx` for the full write-up.
3. Compare `data/rules.csv`/`data/packets.csv` against `output/results.csv`.
4. Browse `screenshots/` for the Home/Rules/Packets/Logs/Settings/Tutorial/About tabs.

## Screenshots

See `screenshots/` — 7 screenshots covering every tab.

## Results

Uses the same 8-rule/8-packet dataset as the C++ firewall engine.
`output/results.csv` confirms correct evaluation, e.g. rule 6 allowing
`172.16.5.25 → 192.168.5.10 TCP` and rule 8 allowing
`192.168.10.15 → 1.1.1.1 TCP`.

## Limitations

- Teaching tool, not a production firewall — no live packet capture.
- Rule matching is string-based rather than a proper network-protocol parser.

## Future Enhancements

- CIDR/port-based matching.
- Import/export of rule sets between the C++ and C# versions.

## Safety and Privacy

- No real secrets, credentials, or private keys are included.
- No private user data is included; all rules/packets are synthetic.

## Ethical Notice

This project is intended strictly for academic learning and does not
interact with any real network.
