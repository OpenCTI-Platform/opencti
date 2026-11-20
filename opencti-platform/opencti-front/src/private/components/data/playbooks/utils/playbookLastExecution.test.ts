import { describe, expect, it } from 'vitest';
import { formatStepDuration, lastExecutionByNode } from './playbookLastExecution';

describe('lastExecutionByNode', () => {
  it('returns an empty map without executions', () => {
    expect(lastExecutionByNode(null).size).toBe(0);
    expect(lastExecutionByNode([]).size).toBe(0);
  });

  it('keeps the outcome of each step from the newest execution, whatever the array order', () => {
    const older = {
      id: 'exec-1',
      execution_start: '2026-11-15T08:00:00.000Z',
      steps: [
        { id: 'exec-1-node-a', status: 'success', duration: 120 },
        { id: 'exec-1-node-b', status: 'error', duration: 40 },
        { id: 'exec-1-node-c', status: 'success', duration: 5 },
      ],
    };
    const newer = {
      id: 'exec-2',
      execution_start: '2026-11-15T09:00:00.000Z',
      steps: [
        { id: 'exec-2-node-a', status: 'error', duration: 300 },
        { id: 'exec-2-node-b', status: 'success', duration: 1500 },
      ],
    };
    const forward = lastExecutionByNode([older, newer]);
    const backward = lastExecutionByNode([newer, older]);
    expect(Object.fromEntries(forward)).toEqual(Object.fromEntries(backward));
    expect(forward.get('node-a')).toEqual({ status: 'error', duration: 300, executionId: 'exec-2' });
    expect(forward.get('node-b')).toEqual({ status: 'success', duration: 1500, executionId: 'exec-2' });
    // a step the newest execution did not reach keeps its last known outcome
    expect(forward.get('node-c')).toEqual({ status: 'success', duration: 5, executionId: 'exec-1' });
  });

  it('reads node ids that contain dashes and ignores steps of another execution', () => {
    const result = lastExecutionByNode([{
      id: 'e9',
      execution_start: '2026-11-15T09:00:00.000Z',
      steps: [
        { id: 'e9-0b8d6c5e-1f2a-4c3d-9e8f-7a6b5c4d3e2f', status: 'success', duration: null },
        { id: 'other-node', status: 'success', duration: 1 },
      ],
    }]);
    expect([...result.keys()]).toEqual(['0b8d6c5e-1f2a-4c3d-9e8f-7a6b5c4d3e2f']);
    expect(result.get('0b8d6c5e-1f2a-4c3d-9e8f-7a6b5c4d3e2f')?.duration).toBeNull();
  });

  it('treats any status other than success as an error', () => {
    const result = lastExecutionByNode([{ id: 'x', execution_start: null, steps: [{ id: 'x-n', status: 'failure', duration: 3 }] }]);
    expect(result.get('n')?.status).toBe('error');
  });
});

describe('formatStepDuration', () => {
  it('formats milliseconds, seconds and minutes', () => {
    expect(formatStepDuration(null)).toBeNull();
    expect(formatStepDuration(-1)).toBeNull();
    expect(formatStepDuration(840)).toBe('840 ms');
    expect(formatStepDuration(2400)).toBe('2.4 s');
    expect(formatStepDuration(42000)).toBe('42 s');
    expect(formatStepDuration(185000)).toBe('3 min 5 s');
    expect(formatStepDuration(120000)).toBe('2 min');
  });
});
