import { describe, expect, it } from 'vitest';
import {
  buildTimelineStatuses,
  capTimelineRead,
  keepNewestTimelineEntries,
  terminalWorkflowStates,
  timelineRefIds,
  toTimelineElement,
} from '../../../../src/modules/timeline/timeline-loader';

describe('Timeline element refs', () => {
  it('should read the refs of a document read with its relations', () => {
    const element = { 'rel_object-marking.internal_id': ['amber', 'pap'], 'rel_created-by.internal_id': ['author'] };
    expect(timelineRefIds(element, 'object-marking')).toEqual(['amber', 'pap']);
    expect(timelineRefIds(element, 'created-by')).toEqual(['author']);
  });

  it('should read the security refs a document read without its relations carries as doc values', () => {
    // The engine converts the doc values of rel_object-marking.internal_id.keyword into the relation type key
    const element = { 'object-marking': ['amber'], granted: ['org-a', 'org-b'], 'created-by': 'author' };
    expect(timelineRefIds(element, 'object-marking')).toEqual(['amber']);
    expect(timelineRefIds(element, 'granted')).toEqual(['org-a', 'org-b']);
    expect(timelineRefIds(element, 'created-by')).toEqual(['author']);
    expect(timelineRefIds({}, 'object-marking')).toEqual([]);
  });

  it('should give a derived element the markings and the author it was read with', () => {
    const element = toTimelineElement({
      internal_id: 'indicator-1',
      standard_id: 'indicator--1',
      entity_type: 'Indicator',
      name: 'Amber indicator',
      'object-marking': ['amber'],
      'created-by': 'author',
    } as any);
    expect(element.markings).toEqual(['amber']);
    expect(element.created_by_id).toEqual('author');
  });

  it('should give a technique the kill chain phases it was read with, with or without its relations', () => {
    // Read without its relations (the default of the engine), the phases come back as doc values under the relation type
    const technique = { internal_id: 'ap-1', standard_id: 'attack-pattern--1', entity_type: 'Attack-Pattern', name: 'Spearphishing' };
    expect(toTimelineElement({ ...technique, 'kill-chain-phase': ['phase-1', 'phase-2'] } as any).kill_chain_phase_ids).toEqual(['phase-1', 'phase-2']);
    expect(toTimelineElement({ ...technique, 'rel_kill-chain-phase.internal_id': ['phase-1'] } as any).kill_chain_phase_ids).toEqual(['phase-1']);
    expect(toTimelineElement(technique as any).kill_chain_phase_ids).toEqual([]);
  });
});

describe('Timeline derivation input bounds', () => {
  it('should keep a family within its bound untouched and not report a truncation', () => {
    const bounds = { truncated: false };
    expect(capTimelineRead(bounds, [1, 2, 3], 3)).toEqual([1, 2, 3]);
    expect(capTimelineRead(bounds, [], 3)).toEqual([]);
    expect(bounds.truncated).toBe(false);
  });

  it('should cap a family read one item past its bound and report the truncation', () => {
    const bounds = { truncated: false };
    expect(capTimelineRead(bounds, [1, 2, 3, 4], 3)).toEqual([1, 2, 3]);
    expect(bounds.truncated).toBe(true);
  });

  it('should keep the truncation reported by an earlier family', () => {
    const bounds = { truncated: false };
    capTimelineRead(bounds, ['a', 'b'], 1);
    expect(capTimelineRead(bounds, ['c'], 5)).toEqual(['c']);
    expect(bounds.truncated).toBe(true);
  });

  it('should keep the newest history entries beyond the bound, in chronological order', () => {
    const bounds = { truncated: false };
    // Read from the newest entry, one past the bound
    expect(keepNewestTimelineEntries(bounds, ['2026-02-06', '2026-02-05', '2026-02-04', '2026-02-03'], 3)).toEqual(['2026-02-04', '2026-02-05', '2026-02-06']);
    expect(bounds.truncated).toBe(true);
    const within = { truncated: false };
    expect(keepNewestTimelineEntries(within, ['2026-02-02', '2026-02-01'], 3)).toEqual(['2026-02-01', '2026-02-02']);
    expect(within.truncated).toBe(false);
  });
});

describe('Timeline workflow statuses', () => {
  const status = (internal_id: string, type: string, order: number, scope?: string | null) => ({ internal_id, name: internal_id, type, order, scope });

  it('should mark the last status of each type as final', () => {
    const statuses = buildTimelineStatuses([
      status('incident-new', 'Case-Incident', 1, 'GLOBAL'),
      status('incident-closed', 'Case-Incident', 5, 'GLOBAL'),
      status('rft-new', 'Case-Rft', 1, 'GLOBAL'),
      status('rft-closed', 'Case-Rft', 2, 'GLOBAL'),
    ]);
    expect(statuses.get('incident-closed')?.is_final).toBe(true);
    expect(statuses.get('incident-new')?.is_final).toBe(false);
    expect(statuses.get('rft-closed')?.is_final).toBe(true);
    expect(statuses.get('rft-new')?.is_final).toBe(false);
  });

  it('should compute the final status of each workflow scope independently', () => {
    const statuses = buildTimelineStatuses([
      status('rfi-new', 'Case-Rfi', 1, 'GLOBAL'),
      status('rfi-closed', 'Case-Rfi', 3, 'GLOBAL'),
      status('access-new', 'Case-Rfi', 1, 'REQUEST_ACCESS'),
      status('access-approved', 'Case-Rfi', 7, 'REQUEST_ACCESS'),
    ]);
    // A higher order in the request access workflow never makes the case workflow's last status non-final
    expect(statuses.get('rfi-closed')?.is_final).toBe(true);
    expect(statuses.get('access-approved')?.is_final).toBe(true);
    expect(statuses.get('rfi-new')?.is_final).toBe(false);
    expect(statuses.get('access-new')?.is_final).toBe(false);
  });

  it('should read a status without scope as part of the case workflow', () => {
    const statuses = buildTimelineStatuses([
      status('legacy-new', 'Case-Incident', 1, null),
      status('incident-closed', 'Case-Incident', 4, 'GLOBAL'),
    ]);
    expect(statuses.get('incident-closed')?.is_final).toBe(true);
    expect(statuses.get('legacy-new')?.is_final).toBe(false);
  });

  // New -> Triage -> Investigating -> Resolved, Triage -> Rejected, New or Triage -> Cancelled, Resolved -> Investigating (reopening)
  const branchingWorkflow = {
    initialState: 'tpl-new',
    transitions: [
      { from: 'tpl-new', to: 'tpl-triage', event: 'triage' },
      { from: 'tpl-triage', to: 'tpl-investigating', event: 'investigate' },
      { from: 'tpl-investigating', to: 'tpl-resolved', event: 'resolve' },
      { from: 'tpl-triage', to: 'tpl-rejected', event: 'reject' },
      { from: ['tpl-new', 'tpl-triage'], to: 'tpl-cancelled', event: 'cancel' },
      { from: 'tpl-resolved', to: 'tpl-investigating', event: 'reopen' },
    ],
  };

  it('should read the terminal states of a workflow defined by transitions, whatever their order', () => {
    const terminal = terminalWorkflowStates(branchingWorkflow);
    // Rejected and Cancelled end shorter branches, Resolved can be reopened: all three are terminal
    expect(Array.from(terminal).sort()).toEqual(['tpl-cancelled', 'tpl-rejected', 'tpl-resolved']);
  });

  it('should mark every terminal state of a workflow defined by transitions as final', () => {
    const withTemplate = (internal_id: string, order: number, template_id: string) => ({ ...status(internal_id, 'Case-Incident', order, 'GLOBAL'), template_id });
    const statuses = buildTimelineStatuses([
      withTemplate('incident-new', 0, 'tpl-new'),
      withTemplate('incident-triage', 1, 'tpl-triage'),
      withTemplate('incident-rejected', 2, 'tpl-rejected'),
      withTemplate('incident-cancelled', 2, 'tpl-cancelled'),
      withTemplate('incident-investigating', 2, 'tpl-investigating'),
      withTemplate('incident-resolved', 3, 'tpl-resolved'),
      status('access-new', 'Case-Incident', 1, 'REQUEST_ACCESS'),
      status('access-approved', 'Case-Incident', 2, 'REQUEST_ACCESS'),
    ], new Map([['Case-Incident', terminalWorkflowStates(branchingWorkflow)]]));
    expect(statuses.get('incident-rejected')?.is_final).toBe(true);
    expect(statuses.get('incident-cancelled')?.is_final).toBe(true);
    expect(statuses.get('incident-resolved')?.is_final).toBe(true);
    expect(statuses.get('incident-investigating')?.is_final).toBe(false);
    expect(statuses.get('incident-new')?.is_final).toBe(false);
    // Another scope keeps its own ordered workflow
    expect(statuses.get('access-approved')?.is_final).toBe(true);
    expect(statuses.get('access-new')?.is_final).toBe(false);
  });
});
