import { describe, expect, it } from 'vitest';
import { InvestigationApprovalKind, InvestigationApprovalStatus, InvestigationRunStatus, TriggerEventType } from '../../../../src/generated/graphql';
import { investigationNotificationMessage, investigationRunEventFor, investigationTriggerEventFor } from '../../../../src/modules/investigationRun/investigationRun-notification';
import type { InvestigationApproval } from '../../../../src/modules/investigationRun/investigationRun-types';
import { buildRun } from './investigationRun-fixtures';

describe('Case Autopilot notifications', () => {
  it('raises an event when a run waits for an approval, completes or fails', () => {
    expect(investigationTriggerEventFor(InvestigationRunStatus.Running, InvestigationRunStatus.AwaitingApproval))
      .toBe(TriggerEventType.InvestigationAwaitingApproval);
    expect(investigationTriggerEventFor(InvestigationRunStatus.AwaitingApproval, InvestigationRunStatus.Completed))
      .toBe(TriggerEventType.InvestigationCompleted);
    expect(investigationTriggerEventFor(InvestigationRunStatus.Running, InvestigationRunStatus.Failed))
      .toBe(TriggerEventType.InvestigationFailed);
  });

  it('raises nothing when the status does not change, on start or on a cancellation', () => {
    expect(investigationTriggerEventFor(InvestigationRunStatus.Running, InvestigationRunStatus.Running)).toBeNull();
    expect(investigationTriggerEventFor(InvestigationRunStatus.AwaitingApproval, InvestigationRunStatus.AwaitingApproval)).toBeNull();
    expect(investigationTriggerEventFor(InvestigationRunStatus.Planned, InvestigationRunStatus.Running)).toBeNull();
    expect(investigationTriggerEventFor(InvestigationRunStatus.Running, InvestigationRunStatus.Cancelled)).toBeNull();
  });

  it('raises an approval event when a gate appears on a run the engine keeps investigating', () => {
    const gate = (id: string, status: InvestigationApprovalStatus): InvestigationApproval => ({
      id,
      kind: InvestigationApprovalKind.Enrichment,
      status,
      description: 'Run a paid connector',
      reason: null,
      connector_id: 'connector-1',
      entity_id: 'entity-1',
      recommendation_id: null,
      created_at: '2026-10-03T10:00:00.000Z',
    });
    const running = buildRun({ run_status: InvestigationRunStatus.Running, approvals: [] });
    const held = buildRun({ run_status: InvestigationRunStatus.Running, approvals: [gate('a1', InvestigationApprovalStatus.Pending)] });
    expect(investigationRunEventFor(running, held)).toBe(TriggerEventType.InvestigationAwaitingApproval);
    // The same gate seen again, or a gate decided, raises nothing.
    expect(investigationRunEventFor(held, held)).toBeNull();
    const decided = buildRun({ run_status: InvestigationRunStatus.Running, approvals: [gate('a1', InvestigationApprovalStatus.Approved)] });
    expect(investigationRunEventFor(held, decided)).toBeNull();
    // A status change keeps its own event.
    const failed = buildRun({ run_status: InvestigationRunStatus.Failed, approvals: [gate('a1', InvestigationApprovalStatus.Pending)] });
    expect(investigationRunEventFor(running, failed)).toBe(TriggerEventType.InvestigationFailed);
  });

  it('names the case and the reason of a failure in the message', () => {
    const run = buildRun({ case_id: 'case-1', status_reason: 'The XTM One investigation engine cannot be reached' });
    expect(investigationNotificationMessage(TriggerEventType.InvestigationAwaitingApproval, run, 'Phishing wave', true))
      .toBe('Case Autopilot investigation of [case] Phishing wave is waiting for an analyst approval');
    expect(investigationNotificationMessage(TriggerEventType.InvestigationCompleted, run, 'Phishing wave', true))
      .toBe('Case Autopilot investigation of [case] Phishing wave is completed');
    expect(investigationNotificationMessage(TriggerEventType.InvestigationFailed, run, 'Phishing wave', true))
      .toBe('Case Autopilot investigation of [case] Phishing wave failed: The XTM One investigation engine cannot be reached');
    const subjectRun = buildRun({ case_id: null, subject_type: 'Incident', status_reason: null });
    expect(investigationNotificationMessage(TriggerEventType.InvestigationFailed, subjectRun, 'Phishing wave', false))
      .toBe('Case Autopilot investigation of [incident] Phishing wave failed');
    // A case still in the run Draft: the event is delivered on the live subject and names it.
    const draftCaseRun = buildRun({ case_id: 'case-in-draft', subject_type: 'Indicator', status_reason: null });
    expect(investigationNotificationMessage(TriggerEventType.InvestigationAwaitingApproval, draftCaseRun, 'evil.example', false))
      .toBe('Case Autopilot investigation of [indicator] evil.example is waiting for an analyst approval');
  });
});
