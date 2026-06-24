"""
SATARK Layer 1 — LLM Prompt Templates

One module per LLM touchpoint. Prompts are separated from provider logic
so they can be updated without touching provider implementations.

Track 1 touchpoints (Section 4.1):
  dynamic_dispatch   — Touchpoint 1: pick call target from candidate nodes
  name_ambiguity     — Touchpoint 2: Layer 4 of 4-layer linking funnel
  semantic_summary   — Touchpoint 3: generate plain English node description

Track 2 call types (Section 7.6):
  track2_narrow      — Type A: narrow disambiguation (2–4 known candidates)
  track2_new_context — Type A*: new context + wider candidate set + GKG context
  track2_classify    — Type B: full classification from domain-filtered taxonomy
"""
