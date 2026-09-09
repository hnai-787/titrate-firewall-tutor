# Project Notes

## Source

Migrated from `air-university-cybersecurity-projects/projects/firewall-tutor-csharp`
into this workspace as an independent project on 2026-09-07.

## Cleanup decisions

- No build output existed in the source folder for this project; nothing was excluded.
- Copied as-is otherwise (source, data, output, docs, screenshots).

## Assumptions

- Group members were originally listed in this README's course-info
  table (verbatim from `docs/firewall-tutor-csharp.docx`'s author list);
  that table was later removed along with other academic framing. The
  original author list is still preserved in the docx.

## Remaining work

- None identified.

## 2026-09-08: Rebuilt as an interactive ACL execution visualizer

### What changed and why

Rather than duplicate `fwlint` (the sibling C++ project) as a second
anomaly-detection engine, this project became the deliberate *teaching*
counterpart: fwlint audits a whole ruleset for structural problems;
Firewall Tutor explains why one specific packet got one specific decision,
field by field, with first-match-stop and implicit-deny made visible
rather than implied. This was a joint decision made explicitly to avoid
two overlapping C++/C# rewrites of the same idea.

The original WinForms app, its CSV data, `.docx` report, and screenshots
were preserved unmodified under `archive/original/`.

### Key engineering decisions and why

- **Multi-field rules, not single-field.** The original engine matched a
  rule against exactly one field (`SourceIp` OR `Protocol` OR ...). The
  rebuild moved to full 5-tuple rules (protocol + source + source port +
  destination + destination port, all ANDed), matching real Cisco ACL
  semantics and enabling the field-by-field explanation table that is the
  whole point of the tool.
- **Discontiguous wildcard masks are supported here, unlike in fwlint.**
  fwlint needs exact whole-policy set algebra and therefore must reject
  masks it can't decompose into disjoint boxes safely. This project only
  ever tests one concrete packet's membership at a time, which is
  well-defined for *any* wildcard pattern (contiguous or not) -- so
  supporting the general case here is both correct and a genuinely
  interesting teaching moment about what wildcard bits mean.
- **Blazor WebAssembly as the primary interface, console as secondary.**
  The differentiating value (field-level tables, first-match visual
  boundary, predict-then-reveal, bit breakdowns, forward/backward
  stepping) needs visual space a terminal can't give without becoming a
  worse version of the same idea. The CLI was still built and kept as a
  first-class, fully-tested interface -- useful for scripting/verification
  and for learners without a GUI -- sharing the exact same
  `FirewallEvaluator` so the two can never disagree.
- **New Cisco ACL parser, not shared code with fwlint.** Same bounded,
  fail-closed subset and design philosophy, but reimplemented in C# rather
  than literally shared, since the two projects are independent
  repositories with different consumers (a whole-policy analyzer vs. a
  single-packet trace generator).
- **.NET 10 SDK and CMake were both missing from this machine** and were
  installed via `winget` as part of this work (`Microsoft.DotNet.SDK.10`),
  matching how the C++ toolchain for `fwlint` was set up in the same
  session.

### Verification performed

`dotnet build` and `dotnet test` were run against the full solution (33/33
tests passing). The Blazor web UI was actually launched (`dotnet run`) and
driven end-to-end in a real browser: rule parsing from all three presets,
packet building with validation, the predict/reveal flow, field-by-field
tables (including a genuine discontiguous-wildcard match), the first
-match stop boundary, the implicit-default fallback, and forward/backward/
jump navigation between rules. One real bug was found and fixed during
that browser verification: the bit-level wildcard breakdown row could
overflow the page horizontally for long binary strings; fixed with a
scrollable table-cell wrapper (`overflow-x:auto; max-width:0` on the
`<td>`), verified by re-measuring `document.body.scrollWidth` before and
after. The CLI's worked example (same two rules, reordered, opposite
result) was run for real and its exact output is what's quoted in the
README, not a description of expected behavior.

### Remaining work / honest limitations

See the README's "Limitations" and "Future Enhancements" -- notably: no
curated lesson/challenge content system, no in-browser drag-and-drop rule
reordering, no deployment/hosting set up yet (not pushed to GitHub in this
task), and no accessibility audit performed.
