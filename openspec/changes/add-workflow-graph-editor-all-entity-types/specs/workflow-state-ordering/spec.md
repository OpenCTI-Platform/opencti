## ADDED Requirements

### Requirement: Cycle-scoped state ordering computation
The workflow state ordering computation SHALL derive each state's display
order as the length of the longest simple path from the initial state to
that state, using a per-path visited set so that a cycle only prevents
ordering of the states genuinely entangled in it, not every state in the
reachable graph.

#### Scenario: Unrelated states keep automatic ordering despite an unrelated cycle
- **WHEN** a workflow definition's reachable state graph contains a cycle
  between two states that is not on any path to a third state
- **THEN** the third state SHALL still receive an automatically computed
  order, and SHALL NOT require a manually supplied `order` value

#### Scenario: States entangled in a cycle still require manual order
- **WHEN** a workflow definition's reachable state graph contains a cycle
  and the ordering computation cannot determine a bounded longest-path
  length for a state on that cycle
- **THEN** that state SHALL still require a manually supplied `order`
  value, consistent with current validation behavior

#### Scenario: Acyclic graphs are ordered the same as before
- **WHEN** a workflow definition's reachable state graph has no cycles
- **THEN** the computed order for each state SHALL be a valid, unique
  progression from the initial state consistent with the current
  behavior for acyclic graphs

### Requirement: Bounded ordering computation with graceful fallback
The state ordering computation SHALL be bounded by a fixed amount of work
so that pathologically large or densely connected graphs cannot cause it
to run unbounded. If the bound is exceeded, the computation SHALL fall
back to requiring a manually supplied `order` only for the affected
states, without failing the overall computation for unaffected states.

#### Scenario: Oversized graph falls back per affected state
- **WHEN** the ordering computation's bounded work limit is exceeded while
  computing the order for a subset of states
- **THEN** only that subset of states requires a manually supplied `order`
  value, and states already successfully ordered are unaffected
