import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getEntitiesListFromCache } from '../../../../src/database/cache';
import { elCount } from '../../../../src/database/engine';
import { fetchProvenanceTelemetry, type ProvenanceTelemetryGauges } from '../../../../src/modules/provenance/provenance-telemetry';
import { listProvenanceTrackedTypes } from '../../../../src/modules/provenance/provenance-tracking';
import { testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/cache')>()),
  getEntitiesListFromCache: vi.fn(),
}));
vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elCount: vi.fn(),
}));
vi.mock('../../../../src/modules/provenance/provenance-tracking', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/provenance/provenance-tracking')>()),
  listProvenanceTrackedTypes: vi.fn(),
}));

const buildGauges = (): ProvenanceTelemetryGauges => ({
  setActiveKnowledgeDecayRulesCount: vi.fn(),
  setProvenanceTrackedRelationshipsCount: vi.fn(),
  setProvenanceCorroboratedRelationshipsCount: vi.fn(),
  setProvenanceStaleKnowledgeCount: vi.fn(),
  setProvenanceConflictingKnowledgeCount: vi.fn(),
});

describe('Provenance telemetry', () => {
  beforeEach(() => {
    vi.mocked(getEntitiesListFromCache).mockReset().mockResolvedValue([
      { active: true, target_scope: 'knowledge' },
      { active: true, target_scope: 'indicator' },
      { active: false, target_scope: 'knowledge' },
      { active: true },
    ] as never);
    vi.mocked(elCount).mockReset().mockResolvedValue(3);
    vi.mocked(listProvenanceTrackedTypes).mockReset().mockResolvedValue(['Malware', 'uses']);
  });

  it('should read nothing and set no gauge while provenance is switched off', async () => {
    const gauges = buildGauges();
    await fetchProvenanceTelemetry(testContext, gauges, false);
    expect(getEntitiesListFromCache).not.toHaveBeenCalled();
    expect(elCount).not.toHaveBeenCalled();
    Object.values(gauges).forEach((gauge) => expect(gauge).not.toHaveBeenCalled());
  });

  it('should count the active knowledge decay rules and the provenance of knowledge while provenance is on', async () => {
    const gauges = buildGauges();
    await fetchProvenanceTelemetry(testContext, gauges, true);
    expect(gauges.setActiveKnowledgeDecayRulesCount).toHaveBeenCalledWith(1);
    expect(elCount).toHaveBeenCalledTimes(4);
    expect(gauges.setProvenanceTrackedRelationshipsCount).toHaveBeenCalledWith(3);
    expect(gauges.setProvenanceCorroboratedRelationshipsCount).toHaveBeenCalledWith(3);
    expect(gauges.setProvenanceStaleKnowledgeCount).toHaveBeenCalledWith(3);
    expect(gauges.setProvenanceConflictingKnowledgeCount).toHaveBeenCalledWith(3);
  });

  it('should only count the types whose provenance is tracked, and nothing when no type is tracked', async () => {
    await fetchProvenanceTelemetry(testContext, buildGauges(), true);
    expect(elCount).toHaveBeenCalledTimes(4);
    vi.mocked(elCount).mock.calls.forEach(([, , , options]) => expect((options as { types?: string[] }).types).toEqual(['Malware', 'uses']));
    vi.mocked(elCount).mockClear();
    vi.mocked(listProvenanceTrackedTypes).mockResolvedValue([]);
    const gauges = buildGauges();
    await fetchProvenanceTelemetry(testContext, gauges, true);
    expect(elCount).not.toHaveBeenCalled();
    expect(gauges.setActiveKnowledgeDecayRulesCount).toHaveBeenCalledWith(1);
    expect(gauges.setProvenanceStaleKnowledgeCount).toHaveBeenCalledWith(0);
    expect(gauges.setProvenanceConflictingKnowledgeCount).toHaveBeenCalledWith(0);
    expect(gauges.setProvenanceTrackedRelationshipsCount).toHaveBeenCalledWith(0);
    expect(gauges.setProvenanceCorroboratedRelationshipsCount).toHaveBeenCalledWith(0);
  });
});
