import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createEntity, createRelation, loadEntity } from '../../../src/database/middleware';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { findByType } from '../../../src/modules/entitySetting/entitySetting-domain';
import { initializeEntityWorkflow } from '../../../src/modules/workflow/domain/workflow-domain';
import { projectWorkflowState } from '../../../src/modules/workflow/domain/workflow-projection';

// `initializeEntityWorkflow` runs synchronously inside `createEntity`'s hot path, so once an
// entity type is migrated to a published workflow, every entity creation gains the store round
// trips it makes (entity-setting lookup, definition lookup, instance lookup, instance write,
// relation write). This is a real cost for bulk STIX-bundle ingestion (workers/connectors
// creating thousands of entities per batch). All store-level dependencies are mocked — the
// benchmark measures the real production `initializeEntityWorkflow` code path, not a synthetic
// reimplementation, so it stays meaningful as a regression gate even though the mocked round
// trips resolve near-instantly rather than at real store latency.

vi.mock('../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  createRelation: vi.fn(),
  loadEntity: vi.fn(),
  updateAttribute: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
  internalLoadById: vi.fn(),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../src/modules/entitySetting/entitySetting-domain', () => ({
  findByType: vi.fn(),
}));

vi.mock('../../../src/utils/draftContext', () => ({
  bypassDraftContext: vi.fn((context) => context),
  getDraftContext: vi.fn(() => undefined),
}));

vi.mock('../../../src/modules/workflow/domain/workflow-projection', () => ({
  projectWorkflowState: vi.fn().mockResolvedValue(undefined),
  resolveProjectionScope: vi.fn((scope: string | undefined) => (scope && scope !== 'standard' ? scope : 'GLOBAL')),
  resolveMappedStatusId: vi.fn(),
}));

vi.mock('../../../src/modules/workflow/engine/workflow-factory', () => ({
  WorkflowFactory: {
    createDefinition: vi.fn(() => ({ getInitialState: () => 'open', hasState: () => true, getTransitions: () => [] })),
    getInstance: vi.fn(() => ({ start: vi.fn().mockResolvedValue(undefined), trigger: vi.fn().mockResolvedValue({ success: true }), getCurrentState: () => 'open' })),
  },
}));

const mockContext = { user: { id: 'ctx-user-id' } } as any;
const mockUser = { id: 'user-id' } as any;

const definitionContent = JSON.stringify({
  initialState: 'open',
  states: [{ statusId: 'open' }, { statusId: 'reviewing' }],
  transitions: [{ from: 'open', to: 'reviewing', event: 'start_review' }],
});

const buildEntities = (count: number) => Array.from({ length: count }).map((_, index) => ({
  id: `entity-${index}`,
  internal_id: `entity-${index}`,
  entity_type: 'Incident',
}));

// Runs `initializeEntityWorkflow` for every entity in the batch and returns elapsed ms.
const benchmarkBatch = async (entities: Record<string, any>[]): Promise<number> => {
  const start = performance.now();
  for (let i = 0; i < entities.length; i += 1) {
    await initializeEntityWorkflow(mockContext, mockUser, entities[i]);
  }
  return performance.now() - start;
};

describe('initializeEntityWorkflow throughput benchmark', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (loadEntity as any).mockResolvedValue(null); // no existing WorkflowInstance yet, every entity is a fresh creation
    (createEntity as any).mockResolvedValue({ id: 'instance-id', internal_id: 'instance-id' });
    (createRelation as any).mockResolvedValue({});
  });

  const mockNoWorkflowConfigured = () => {
    (findByType as any).mockResolvedValue(undefined);
    (storeLoadById as any).mockResolvedValue(null);
  };

  const mockWorkflowConfigured = () => {
    (findByType as any).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-def-id' });
    (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
      if (id === 'workflow-def-id') {
        return Promise.resolve({ id: 'workflow-def-id', name: 'wf', published_version: { id: 'v1', content: definitionContent, validation_errors: [] } });
      }
      return Promise.resolve(null);
    });
  };

  it('scales near-linearly (not quadratically) as the ingestion batch size grows, before vs after workflow migration', async () => {
    const sizes = [500, 2000, 8000];
    const withWorkflowMs: number[] = [];

    for (let i = 0; i < sizes.length; i += 1) {
      const entities = buildEntities(sizes[i]);
      mockWorkflowConfigured();
      withWorkflowMs.push(await benchmarkBatch(entities));
    }

    console.log('[BENCHMARK] initializeEntityWorkflow — with published workflow (ms) for sizes', sizes, '=>', withWorkflowMs);

    // Growth factor gate: quadrupling batch size (500 -> 2000 -> 8000, both 4x) should roughly
    // quadruple runtime, not multiply it ~16x — catches an accidental O(n^2) regression in the
    // hot path (e.g. a per-entity full-table scan) long before it hits a real ingestion pipeline.
    const withWorkflowGrowth1 = withWorkflowMs[1] / Math.max(withWorkflowMs[0], 1);
    const withWorkflowGrowth2 = withWorkflowMs[2] / Math.max(withWorkflowMs[1], 1);

    console.log('[BENCHMARK] with-workflow growth factors (should be well under 16x):', withWorkflowGrowth1, withWorkflowGrowth2);

    expect(withWorkflowGrowth1).toBeLessThan(10);
    expect(withWorkflowGrowth2).toBeLessThan(10);
  });

  it('quantifies the per-entity overhead of a published workflow on the entity-creation hot path', async () => {
    const size = 5000;
    const entities = buildEntities(size);

    mockNoWorkflowConfigured();
    const baselineMs = await benchmarkBatch(entities);

    mockWorkflowConfigured();
    const withWorkflowMs = await benchmarkBatch(entities);

    const perEntityOverheadMs = (withWorkflowMs - baselineMs) / size;

    console.log(`[BENCHMARK] ${size}-entity batch — no workflow: ${baselineMs.toFixed(2)}ms, with published workflow: ${withWorkflowMs.toFixed(2)}ms, per-entity overhead: ${perEntityOverheadMs.toFixed(4)}ms`);

    expect(createEntity).toHaveBeenCalledTimes(size);
    expect(projectWorkflowState).toHaveBeenCalledTimes(size);

    // Canary rollout gate: record this figure alongside a type's canary observation window
    // before migrating a high-cardinality type (Indicators/Observables). With mocked
    // (near-instant) store round trips this bounds only the *fixed* per-entity overhead of
    // `initializeEntityWorkflow`'s control flow itself — real store round-trip latency must be
    // added on top when sizing an actual production canary.
    expect(perEntityOverheadMs).toBeLessThan(5);
  });
});
