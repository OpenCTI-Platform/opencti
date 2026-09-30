import { describe, expect, it } from 'vitest';
import { abandonedWorkAction } from '../../../src/manager/workClosing';

const NOW = Date.parse('2026-09-30T12:00:00.000Z');

describe('connector manager: closing the works of finished runs (ADR 0007)', () => {
  it('releases a multipart work whose connector never called to_processed', () => {
    expect(abandonedWorkAction({ is_multipart: 'true', is_processed: 'false' }, NOW, 60)).toBe('release');
  });

  it('leaves a released work alone while it still progresses', () => {
    const state = { is_multipart: 'true', is_processed: 'true', import_last_processed: '2026-09-30T11:30:00.000Z' };
    expect(abandonedWorkAction(state, NOW, 60)).toBe('none');
  });

  it('forces a work that made no progress for the stale delay', () => {
    const state = { is_multipart: 'false', import_last_processed: '2026-09-30T10:30:00.000Z' };
    expect(abandonedWorkAction(state, NOW, 60)).toBe('force');
  });

  it('forces a work that never reported anything', () => {
    expect(abandonedWorkAction({ is_multipart: 'false' }, NOW, 60)).toBe('force');
  });

  it('does nothing without a Redis state', () => {
    expect(abandonedWorkAction(null, NOW, 60)).toBe('none');
  });
});
