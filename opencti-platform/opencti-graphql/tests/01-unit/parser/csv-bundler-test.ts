import { beforeEach, describe, expect, it, vi } from 'vitest';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';

vi.mock('../../../src/parser/csv-parser', () => ({
  parsingProcess: vi.fn(async () => [['line1']]),
}));
vi.mock('../../../src/parser/csv-mapper', () => ({
  handleRefEntities: vi.fn(async () => ({})),
  mappingProcess: vi.fn(async () => ([{ entity_type: 'Indicator', id: 'input--1' }])),
}));
vi.mock('../../../src/database/stix-2-1-converter', () => ({
  convertStoreToStix_2_1: vi.fn(() => ({
    id: 'indicator--test',
    type: 'indicator',
    extensions: { [STIX_EXT_OCTI]: {} },
  })),
}));

const pushBundleToWorkerMock = vi.fn(async (_context: any, _user: any, _connectorId: any, _message: any) => undefined);
vi.mock('../../../src/database/rabbitmq', () => ({
  pushBundleToWorker: pushBundleToWorkerMock,
}));

const { generateAndSendBundleProcess } = await import('../../../src/parser/csv-bundler');

describe('csv-bundler: worker expectations tracking', () => {
  beforeEach(() => {
    pushBundleToWorkerMock.mockClear();
  });

  it('sends the bundle with the work_id so pushBundleToWorker tracks real per-object expectations', async () => {
    const opts = {
      workId: 'work--1',
      applicantUser: { id: 'user--1', internal_id: 'user--1' } as any,
      entity: undefined,
      csvMapper: {} as any,
      connectorId: 'connector--1',
    };

    await generateAndSendBundleProcess({} as any, ['line1'], opts);

    expect(pushBundleToWorkerMock).toHaveBeenCalledTimes(1);
    const message = pushBundleToWorkerMock.mock.calls[0][3];
    expect(message).toMatchObject({ work_id: 'work--1' });
  });
});

describe('csv-bundler: stopping the feed during a run', () => {
  const baseOpts = {
    workId: 'work--1',
    applicantUser: { id: 'user--1', internal_id: 'user--1' } as any,
    entity: undefined,
    csvMapper: {} as any,
    connectorId: 'connector--1',
  };

  beforeEach(() => {
    pushBundleToWorkerMock.mockClear();
  });

  it('sends nothing and reports the run as aborted when the feed is stopped', async () => {
    const isStopped = vi.fn(async () => true);

    const result = await generateAndSendBundleProcess({} as any, ['line1'], { ...baseOpts, isStopped });

    expect(isStopped).toHaveBeenCalled();
    expect(pushBundleToWorkerMock).not.toHaveBeenCalled();
    expect(result).toMatchObject({ aborted: true, bundleCount: 0, objectCount: 0 });
  });

  it('sends the bundle when the feed is still running', async () => {
    const isStopped = vi.fn(async () => false);

    const result = await generateAndSendBundleProcess({} as any, ['line1'], { ...baseOpts, isStopped });

    expect(pushBundleToWorkerMock).toHaveBeenCalledTimes(1);
    expect(result).toMatchObject({ aborted: false, bundleCount: 1 });
  });
});
