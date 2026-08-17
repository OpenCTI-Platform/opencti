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

  it('opts in to trackExpectations so the worker gets real per-object expectations', async () => {
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
    expect(message).toMatchObject({ work_id: 'work--1', trackExpectations: true });
  });
});
