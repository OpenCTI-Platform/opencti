import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ENTITY_TYPE_WORK } from '../../../src/schema/internalObject';

const mockElPaginate = vi.fn();
const mockAddFilter = vi.fn();

vi.mock('../../../src/database/engine', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/database/engine')>();
  return {
    ...actual,
    elPaginate: (...args: unknown[]) => mockElPaginate(...args),
  };
});

vi.mock('../../../src/utils/filtering/filtering-utils', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/utils/filtering/filtering-utils')>();
  return {
    ...actual,
    addFilter: (...args: unknown[]) => mockAddFilter(...args),
  };
});

import { findWorkPaginated, worksForConnector, worksForSource } from '../../../src/domain/work';

describe('Work domain query options', () => {
  const context = {} as any;
  const user = {} as any;

  beforeEach(() => {
    mockElPaginate.mockReset();
    mockAddFilter.mockReset();
    mockElPaginate.mockResolvedValue([]);
  });

  it('findWorkPaginated should scope queries to Work entity type', async () => {
    await findWorkPaginated(context, user, { first: 10 });

    expect(mockElPaginate).toHaveBeenCalledTimes(1);
    const [, , , options] = mockElPaginate.mock.calls[0];
    expect(options.types).toEqual([ENTITY_TYPE_WORK]);
    expect(options.type).toBeUndefined();
  });

  it('worksForConnector should scope queries to Work entity type', async () => {
    const connectorFilter = { mode: 'and', filters: [{ key: 'connector_id', values: ['connector-id'] }], filterGroups: [] };
    mockAddFilter.mockReturnValue(connectorFilter);

    await worksForConnector(context, user, 'connector-id', { first: 20 });

    expect(mockElPaginate).toHaveBeenCalledTimes(1);
    const [, , , options] = mockElPaginate.mock.calls[0];
    expect(options.types).toEqual([ENTITY_TYPE_WORK]);
    expect(options.type).toBeUndefined();
    expect(options.filters).toEqual(connectorFilter);
  });

  it('worksForSource should chain source and event filters and keep Work scoping', async () => {
    const sourceFilter = { mode: 'and', filters: [{ key: 'event_source_id', values: ['source-id'] }], filterGroups: [] };
    const sourceAndEventFilter = {
      mode: 'and',
      filters: [
        { key: 'event_source_id', values: ['source-id'] },
        { key: 'event_type', values: ['import'] },
      ],
      filterGroups: [],
    };
    mockAddFilter
      .mockReturnValueOnce(sourceFilter)
      .mockReturnValueOnce(sourceAndEventFilter);

    await worksForSource(context, user, 'source-id', { first: 15, type: 'import' });

    expect(mockAddFilter).toHaveBeenNthCalledWith(1, null, 'event_source_id', 'source-id');
    expect(mockAddFilter).toHaveBeenNthCalledWith(2, sourceFilter, 'event_type', 'import');
    const [, , , options] = mockElPaginate.mock.calls[0];
    expect(options.types).toEqual([ENTITY_TYPE_WORK]);
    expect(options.type).toBeUndefined();
    expect(options.filters).toEqual(sourceAndEventFilter);
  });
});
