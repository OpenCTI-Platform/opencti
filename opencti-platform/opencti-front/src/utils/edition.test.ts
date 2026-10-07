import { describe, expect, it } from 'vitest';
import { convertEventTypes, knowledgeEventTypesOptions } from './edition';

describe('Trigger event type options', () => {
  it('offers the Case Autopilot events only in Enterprise Edition', () => {
    expect(knowledgeEventTypesOptions(false).map(({ value }) => value)).toEqual(['create', 'update', 'delete']);
    expect(knowledgeEventTypesOptions(true).map(({ value }) => value)).toEqual([
      'create',
      'update',
      'delete',
      'investigation_awaiting_approval',
      'investigation_completed',
      'investigation_failed',
    ]);
  });

  it('still labels every saved event type, whatever the edition', () => {
    const trigger = { event_types: ['create', 'investigation_completed', 'unknown'] };
    expect(convertEventTypes(trigger).map(({ label }: { label: string }) => label)).toEqual([
      'Creation',
      'Investigation completed',
    ]);
  });
});
