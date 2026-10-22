import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { extractGraphAnalyticsImpact } from '../../../src/manager/graphAnalyticsManager';
import type { DataEvent, SseEvent } from '../../../src/types/event';

const event = (type: string, data: Record<string, unknown>, context?: Record<string, unknown>): SseEvent<DataEvent> => ({
  id: '1-0',
  event: type,
  data: { type, scope: 'external', origin: {}, message: '', version: '4', data, ...(context ? { context } : {}) } as unknown as DataEvent,
});

const ext = (values: Record<string, unknown>) => ({ 'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': values });

describe('graph analytics manager stream impact', () => {
  it('should mark both ends of a relationship', () => {
    const impact = extractGraphAnalyticsImpact(event('create', { type: 'relationship', extensions: ext({ id: 'rel', source_ref: 'from-id', target_ref: 'to-id' }) }));
    expect(impact).toEqual({ dirty: ['from-id', 'to-id'], removed: [] });
  });

  it('should mark both ends of a sighting', () => {
    const impact = extractGraphAnalyticsImpact(event('delete', { type: 'sighting', extensions: ext({ id: 's', sighting_of_ref: 'indicator', where_sighted_refs: ['org-a', 'org-b'] }) }));
    expect(impact).toEqual({ dirty: ['indicator', 'org-a', 'org-b'], removed: [] });
  });

  it('should mark created profiled entities only', () => {
    expect(extractGraphAnalyticsImpact(event('create', { type: 'intrusion-set', extensions: ext({ id: 'is', type: 'Intrusion-Set' }) })).dirty).toEqual(['is']);
    expect(extractGraphAnalyticsImpact(event('create', { type: 'note', extensions: ext({ id: 'n', type: 'Note' }) })).dirty).toEqual([]);
  });

  it('should remove deleted entities and merged sources', () => {
    expect(extractGraphAnalyticsImpact(event('delete', { type: 'malware', extensions: ext({ id: 'm', type: 'Malware' }) }))).toEqual({ dirty: [], removed: ['m'] });
    const merge = event('merge', { type: 'malware', extensions: ext({ id: 'target', type: 'Malware' }) }, {
      sources: [{ extensions: ext({ id: 'source-1' }) }, { extensions: ext({ id: 'source-2' }) }],
    });
    expect(extractGraphAnalyticsImpact(merge)).toEqual({ dirty: ['target'], removed: ['source-1', 'source-2'] });
  });

  it('should only consider report updates, which change containment features', () => {
    expect(extractGraphAnalyticsImpact(event('update', { type: 'report', extensions: ext({ id: 'r', type: 'Report' }) })).dirty).toEqual(['r']);
    expect(extractGraphAnalyticsImpact(event('update', { type: 'malware', extensions: ext({ id: 'm', type: 'Malware' }) })).dirty).toEqual([]);
  });

  it('should ignore events without the OpenCTI extension', () => {
    expect(extractGraphAnalyticsImpact(event('create', { type: 'relationship' }))).toEqual({ dirty: [], removed: [] });
  });
});
