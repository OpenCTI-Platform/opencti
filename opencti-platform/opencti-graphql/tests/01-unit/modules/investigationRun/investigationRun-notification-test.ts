import { describe, expect, it } from 'vitest';
import { InvestigationRunStatus, TriggerEventType } from '../../../../src/generated/graphql';
import { investigationNotificationMessage, investigationTriggerEventFor } from '../../../../src/modules/investigationRun/investigationRun-notification';
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

  it('names the case and the reason of a failure in the message', () => {
    const run = buildRun({ case_id: 'case-1', status_reason: 'The XTM One investigation engine cannot be reached' });
    expect(investigationNotificationMessage(TriggerEventType.InvestigationAwaitingApproval, run, 'Phishing wave'))
      .toBe('Case Autopilot investigation of [case] Phishing wave is waiting for an analyst approval');
    expect(investigationNotificationMessage(TriggerEventType.InvestigationCompleted, run, 'Phishing wave'))
      .toBe('Case Autopilot investigation of [case] Phishing wave is completed');
    expect(investigationNotificationMessage(TriggerEventType.InvestigationFailed, run, 'Phishing wave'))
      .toBe('Case Autopilot investigation of [case] Phishing wave failed: The XTM One investigation engine cannot be reached');
    const subjectRun = buildRun({ case_id: null, subject_type: 'Incident', status_reason: null });
    expect(investigationNotificationMessage(TriggerEventType.InvestigationFailed, subjectRun, 'Phishing wave'))
      .toBe('Case Autopilot investigation of [incident] Phishing wave failed');
  });
});
