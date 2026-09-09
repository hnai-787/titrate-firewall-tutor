# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- Deployed to GitHub Pages: https://hnai-787.github.io/titrate-firewall-tutor/
- GitHub and maker-attribution links in the web UI's top bar.
- The project's own icon as the web UI's favicon and nav-bar logo.

### Changed

- Web UI now identifies itself as "Titrate" (page title, nav-bar brand,
  heading) instead of the internal "Firewall Tutor" working name.
- `archive/original/` and the root `data/`, `output/`, `docs/`, and
  `screenshots/` folders (all original-WinForms artifacts) moved out of
  this repository into a personal academic-archive repo; README updated
  with a `TODO` pointer until that repo is published.
- Removed `PROJECT_NOTES.md`.

### Fixed

## [1.0.0] - 2026-09-08

### Added

- Rebuilt the project as an interactive ACL execution visualizer,
  replacing the WinForms tabbed app (preserved unmodified under
  `archive/original/`).
- `FirewallTutor.Core`: multi-field (protocol/source/source port/
  destination/destination port) rule model, a real bounded-subset Cisco
  extended ACL parser (fails closed on unsupported syntax), and
  `FirewallEvaluator.Evaluate` producing a full `EvaluationTrace` --
  every rule considered, every field checked, with a plain-English
  explanation for each pass/fail.
- Bit-level wildcard breakdown, including genuinely discontiguous masks
  (safe here since evaluation only ever tests one concrete packet, unlike
  fwlint's whole-policy exact-set-algebra requirements).
- `FirewallTutor.Web`: Blazor WebAssembly UI (client-only, no backend) with
  rule presets, a packet builder, predict-then-reveal, and forward/
  backward/jump step-through navigation over the immutable trace.
- `FirewallTutor.Cli`: Spectre.Console terminal step-through using the
  identical `FirewallEvaluator`, so the CLI and web UI can never disagree.
- 33 xUnit tests covering address/port/protocol matching, first-match-wins
  evaluation semantics (including the classic broad-before-specific vs.
  specific-before-broad ordering lesson), and the parser's happy and
  fail-closed paths.
- Two example ACLs (`examples/ordering-demo.acl` and
  `ordering-demo-reordered.acl`) demonstrating, with real captured CLI
  output, that reordering the same two rules flips the decision for the
  same packet.

### Changed

- `README.md` rewritten to document the new tool while preserving the
  original course info and problem statement.
