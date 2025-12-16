import { describe, expect, it } from 'vitest';
import { historyMessage } from '../../../src/manager/historyManager';
import type { Change } from '../../../src/types/event';

describe('historyMessage tests', () => {
  it('should generate history message for single replace', () => {
    const changes = [{
      field: 'Description',
      previous: [],
      new: ['description'],
    }];
    const message = historyMessage(changes);
    expect(message).toEqual('replaces `description` in `Description`');
  });
  it('should generate history message for single add', () => {
    const changes = [{
      added: ['attack-pattern'],
      field: 'Label',
      new: ['attack-pattern'],
      previous: [],
      removed: [],
    }];
    const message = historyMessage(changes);
    expect(message).toEqual('adds `attack-pattern` in `Label`');
  });
  it('should generate history message for single remove', () => {
    const changes = [{
      added: [],
      field: 'Markings',
      new: [],
      previous: ['TLP:GREEN'],
      removed: ['TLP:GREEN'],
    }];
    const message = historyMessage(changes);
    expect(message).toEqual('removes `TLP:GREEN` in `Markings`');
  });
  it('should generate history message for multiple replace', () => {
    const changes = [{
      field: 'Description',
      previous: [],
      new: ['description'],
    },
    {
      field: 'Workflow status',
      previous: ['status1'],
      new: ['status2'] }];
    const message = historyMessage(changes);
    expect(message).toEqual('replaces `description` in `Description` - `status2` in `Workflow status`');
  });
  it('should generate history message for more than 3 replaces', () => {
    const changes = [{
      field: 'Description',
      previous: [],
      new: ['description'],
    },
    {
      field: 'Confidence',
      previous: [58],
      new: [52],
    },
    {
      field: 'Workflow status',
      previous: ['status1'],
      new: ['status2'] },
    {
      field: 'Reliability',
      previous: ['A - Completely reliable'],
      new: ['B - Usually reliable'],
      added: [],
      removed: [],
    },
    ];
    const message = historyMessage(changes as Change[]);
    expect(message).toEqual('replaces `description` in `Description` - `52` in `Confidence` - `status2` in `Workflow status` - `B - Usually reliable` in `Reliability` and 1 more operations');
  });
  it('should generate history message for add and remove update', () => {
    const changes = [
      {
        added: ['attack-pattern'],
        field: 'Label',
        new: ['attack-pattern'],
        previous: [],
        removed: [],
      },
      {
        added: [],
        field: 'Markings',
        new: [],
        previous: ['TLP:GREEN'],
        removed: ['TLP:GREEN'],
      },
    ];
    const message = historyMessage(changes as Change[]);
    expect(message).toEqual('adds `attack-pattern` in `Label` | removes `TLP:GREEN` in `Markings`');
  });
});
