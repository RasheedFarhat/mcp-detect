# MCP Detect project objective

MCP Detect is an open-source research lab for reproducible detection of abuse
across Model Context Protocol traffic and authorization boundaries.

## Objective

Make MCP security claims inspectable. Every published result should connect a
specific threat model to source, telemetry, detection logic, frozen evidence,
and a repeatable verification command. Limitations and evasions are first-class
outputs.

## Near-term roadmap

1. Keep the sample and complete corpus reproducible from a clean public clone.
2. Add independently authored or held-out telemetry without overstating what it
   establishes.
3. Expand detection coverage only when a failure mode has a defensible signal
   and regression fixture.
4. Publish small MCP boundary notes that show architecture, trust decisions,
   failure modes, and defensive verification.
5. Improve contributor ergonomics, CI, and evidence provenance.

## Non-goals

- Certification or a security guarantee.
- A hosted dashboard, gateway, or continuous-monitoring product.
- Production exploitation or unapproved access.
- Accuracy claims based only on project-authored fixtures.
- Adding rules merely to increase a coverage count.

## Evidence standard

A detection is not complete until its inputs, rule or algorithm, expected
outcome, known gaps, and reproduction path are committed together. Synthetic
evidence must be labeled synthetic. Frozen engine output must be pinned to the
rules that produced it and invalidated when those rules change.
