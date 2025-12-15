import { describe, expect, it } from 'vitest';
import { historyMessage } from '../../../src/manager/historyManager';

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
});
