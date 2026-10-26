import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type ConnectorWork, getConclusiveWork, getWorkFailure, loadConnectorsRuntimeState } from '../../../../src/modules/ingestionHealth/ingestionHealth-connectorWorks';
import type { BasicStoreEntityConnector, ConnectorInfo } from '../../../../src/modules/connector/connector-types';
import type { RuntimeDataReadContext } from '../../../../src/modules/ingestionHealth/ingestionHealth-registry';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { worksForConnector } from '../../../../src/domain/work';
import { addFilter } from '../../../../src/utils/filtering/filtering-utils';
import { FilterOperator } from '../../../../src/generated/graphql';

vi.mock('../../../../src/database/middleware-loader', async (importActual) => ({
  ...(await importActual<typeof import('../../../../src/database/middleware-loader')>()),
  fullEntitiesList: vi.fn(),
}));
vi.mock('../../../../src/domain/work', async (importActual) => ({
  ...(await importActual<typeof import('../../../../src/domain/work')>()),
  worksForConnector: vi.fn(),
}));
// Lowered so that the bound shows with a few connectors
vi.mock('../../../../src/database/engine', async (importActual) => ({
  ...(await importActual<typeof import('../../../../src/database/engine')>()),
  ES_MAX_CONCURRENCY: 2,
}));

const RUN_END = '2026-10-26T11:00:00.000Z';
const state = (last_work?: ConnectorWork, connector_type = 'EXTERNAL_IMPORT', last_run_datetime: string | null = RUN_END) => ({
  connector_type,
  connector_info: { last_run_datetime } as ConnectorInfo,
  last_work,
});

describe('loadConnectorsRuntimeState', () => {
  const READ = { context: {}, user: {} } as RuntimeDataReadContext;
  const PROCESSED_ONLY = addFilter(null, 'processed_time', [], FilterOperator.NotNil);
  const ingestor = (internal_id: string) => ({ internal_id, entity_type: 'Connector' });
  const connectorsOfTypes = (types: Record<string, string>) => {
    const connectors = Object.entries(types).map(([internal_id, connector_type]) => ({ internal_id, connector_type, connector_info: null }));
    vi.mocked(fullEntitiesList).mockResolvedValue(connectors as unknown as BasicStoreEntityConnector[]);
    return Object.keys(types).map(ingestor);
  };

  beforeEach(() => {
    vi.mocked(worksForConnector).mockReset();
  });

  it('should read the most recent processed work of every type but STREAM, EXTERNAL_IMPORT included: an open work says nothing', async () => {
    const work = { timestamp: '2026-10-26T10:59:00Z', processed_time: '2026-10-26T10:59:58Z' };
    // work.js is untyped: the hits are typed as store elements
    vi.mocked(worksForConnector).mockResolvedValue([work] as never);
    const ingestors = connectorsOfTypes({ import: 'EXTERNAL_IMPORT', enrichment: 'INTERNAL_ENRICHMENT' });
    const states = await loadConnectorsRuntimeState(ingestors, READ);
    expect(worksForConnector).toHaveBeenCalledWith(READ.context, READ.user, 'import', { first: 1, filters: PROCESSED_ONLY });
    expect(worksForConnector).toHaveBeenCalledWith(READ.context, READ.user, 'enrichment', { first: 1, filters: PROCESSED_ONLY });
    expect(states.get('import')?.last_work).toBe(work);
  });

  it('should not read the works of a STREAM connector, which has none', async () => {
    const states = await loadConnectorsRuntimeState(connectorsOfTypes({ stream: 'STREAM' }), READ);
    expect(worksForConnector).not.toHaveBeenCalled();
    expect(states.get('stream')).toEqual({ connector_type: 'STREAM', connector_info: null, last_work: undefined });
  });

  it('should read at most ES_MAX_CONCURRENCY connectors at once', async () => {
    let running = 0;
    let maxRunning = 0;
    vi.mocked(worksForConnector).mockImplementation(async () => {
      running += 1;
      maxRunning = Math.max(maxRunning, running);
      await new Promise((resolve) => {
        setTimeout(resolve, 5);
      });
      running -= 1;
      return [];
    });
    const states = await loadConnectorsRuntimeState(connectorsOfTypes({ c1: 'EXTERNAL_IMPORT', c2: 'EXTERNAL_IMPORT', c3: 'EXTERNAL_IMPORT', c4: 'EXTERNAL_IMPORT', c5: 'EXTERNAL_IMPORT' }), READ);
    expect(states.size).toBe(5);
    expect(maxRunning).toBe(2);
  });

  it('should reject when a read fails: a failure must not be read as a missing value', async () => {
    vi.mocked(worksForConnector).mockRejectedValue(new Error('elastic unavailable'));
    await expect(loadConnectorsRuntimeState(connectorsOfTypes({ c1: 'EXTERNAL_IMPORT' }), READ)).rejects.toThrow('elastic unavailable');
  });
});

describe('getConclusiveWork', () => {
  it('should be conclusive for a processed work of the last run', () => {
    const work = { timestamp: '2026-10-26T10:59:00Z', processed_time: '2026-10-26T10:59:58Z' };
    expect(getConclusiveWork(state(work))).toBe(work);
  });

  it('should not be conclusive for an open or force-closed work (no processed_time), should one be given', () => {
    expect(getConclusiveWork(state({ timestamp: '2026-10-26T10:59:00Z', processed_time: null }))).toBeUndefined();
  });

  it('should not be conclusive when the last run left no processed work (processed long before last_run_datetime)', () => {
    expect(getConclusiveWork(state({ timestamp: '2026-10-26T09:59:00Z', processed_time: '2026-10-26T09:59:58Z' }))).toBeUndefined();
  });

  it('should skip the last run rule when last_run_datetime is unknown', () => {
    const work = { timestamp: '2026-10-26T09:59:00Z', processed_time: '2026-10-26T09:59:58Z' };
    expect(getConclusiveWork(state(work, 'EXTERNAL_IMPORT', null))).toBe(work);
  });

  it('should not be conclusive without any work (purged)', () => {
    expect(getConclusiveWork(state(undefined))).toBeUndefined();
  });
});

describe('getWorkFailure', () => {
  it('should decide the failure on entries without source, and read the CONNECTOR messages first', () => {
    const work = {
      timestamp: 't',
      processed_time: 't',
      errors: [
        { message: '{"type":"indicator"}', source: '{"id":"x"}' },
        { message: 'Connector\'s work finished gracefully', source: null },
        { message: '401 Client Error: Unauthorized for url: https://api.example.com/x', source: 'CONNECTOR' },
      ],
    };
    expect(getWorkFailure(work)).toEqual({
      failed: true,
      messages: ['401 Client Error: Unauthorized for url: https://api.example.com/x', 'Connector\'s work finished gracefully'],
    });
  });

  it('should not count worker errors (with a source other than CONNECTOR) as a failure', () => {
    expect(getWorkFailure({ timestamp: 't', errors: [{ message: 'Element is too large', source: 'Element x' }] }).failed).toBe(false);
  });
});
