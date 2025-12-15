import { describe, expect, it } from 'vitest';
import { historyMessage } from '../../../src/manager/historyManager';
import type { Change } from '../../../src/types/event';

describe('historyMessage tests', () => {
  it('should generate history message for Description update', () => {
    const changes = [{
      field: 'Description',
      previous: [],
      new: ['description'],
    }];
    const message = historyMessage('update', changes);
    expect(message).toEqual('updates description in Description');
  });
  it('should generate history message for multiple update', () => {
    const changes = [{
      field: 'Description',
      previous: [],
      new: ['description'],
    },
    {
      field: 'Malware types',
      previous: ['backdoor', 'bootkit'],
      new: ['backdoor'],
      added: [],
      removed: ['bootkit'],
    }];
    const message = historyMessage('update', changes);
    expect(message).toEqual('updates description in Description - backdoor in Malware types');
  });
  it('should generate history message for multiple update', () => {
    const changes = [{
      field: 'Description',
      previous: [],
      new: ['description'],
    },
    {
      field: 'Malware types',
      previous: ['backdoor', 'bootkit'],
      new: ['backdoor'],
      added: [],
      removed: ['bootkit'],
    },
    {
      field: 'Confidence',
      previous: [58],
      new: [52],
    },
    {
      field: 'Workflow status',
      previous: ['status1'],
      new: ['status2'] }];
    const message = historyMessage('update', changes as Change[]);
    expect(message).toEqual('updates description in Description - backdoor in Malware types - 52 in Confidence - status2 in Workflow status and 1 more operations');
  });
});
