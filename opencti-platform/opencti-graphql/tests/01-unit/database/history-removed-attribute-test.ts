import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { generateMessageFromChanges } from '../../../src/database/data-changes';

describe('history of an attribute removed from the schema', () => {
  // Procedures recorded observable edits under procedureObservables before it became has-observable relationships.
  const change = { field: 'Procedure--procedureObservables', changes_added: [{ raw: 'observable-1' }], changes_removed: [] };

  it('still builds the history message instead of failing', () => {
    const message = generateMessageFromChanges({}, [change] as any);
    expect(message).toEqual('replaces `observable-1` in `Observables`');
  });
});
