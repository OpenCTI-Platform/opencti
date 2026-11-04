import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ENTITY_TYPE_WORK } from '../../../src/schema/internalObject';
import { findExportApplicantId, findWorkPaginated, loadExportWorksAsProgressFiles, worksForConnector, worksForSource } from '../../../src/domain/work';
import { ADMIN_USER } from '../../utils/testQuery';

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

  describe('findExportApplicantId', () => {
    it('should return the user of the export work named after the file', async () => {
      const nameFilter = { mode: 'and', filters: [{ key: 'name', values: ['export.json'] }], filterGroups: [] };
      const nameAndSourceFilter = { mode: 'and', filters: [{ key: 'event_source_id', values: ['export/Report/report-id'] }], filterGroups: [nameFilter] };
      const fullFilter = { mode: 'and', filters: [{ key: 'event_type', values: ['INTERNAL_EXPORT_FILE'] }], filterGroups: [nameAndSourceFilter] };
      mockAddFilter
        .mockReturnValueOnce(nameFilter)
        .mockReturnValueOnce(nameAndSourceFilter)
        .mockReturnValueOnce(fullFilter);
      mockElPaginate.mockResolvedValue([{ id: 'work-id', user_id: 'applicant-id' }]);

      const applicantId = await findExportApplicantId(context, user, 'export/Report/report-id', 'export.json');

      expect(applicantId).toEqual('applicant-id');
      expect(mockAddFilter).toHaveBeenNthCalledWith(1, null, 'name', 'export.json');
      expect(mockAddFilter).toHaveBeenNthCalledWith(2, nameFilter, 'event_source_id', 'export/Report/report-id');
      expect(mockAddFilter).toHaveBeenNthCalledWith(3, nameAndSourceFilter, 'event_type', 'INTERNAL_EXPORT_FILE');
      const [, , , options] = mockElPaginate.mock.calls[0];
      expect(options.filters).toEqual(fullFilter);
      expect(options.first).toEqual(1);
    });

    it('should return undefined when no export work matches', async () => {
      mockElPaginate.mockResolvedValue([]);

      const applicantId = await findExportApplicantId(context, user, 'export/Report/report-id', 'export.json');

      expect(applicantId).toBeUndefined();
    });
  });

  describe('loadExportWorksAsProgressFiles', () => {
    it('should only keep the exports asked by the given user', async () => {
      const userFilter = { mode: 'and', filters: [{ key: 'user_id', values: ['user-id'] }], filterGroups: [] };
      mockAddFilter.mockReturnValueOnce(userFilter);

      await loadExportWorksAsProgressFiles(context, user, 'export/Report/report-id', { userId: 'user-id' });

      expect(mockAddFilter).toHaveBeenNthCalledWith(1, null, 'user_id', 'user-id');
      expect(mockAddFilter).toHaveBeenNthCalledWith(2, userFilter, 'event_source_id', 'export/Report/report-id');
    });

    it('should keep all exports for bypass users', async () => {
      const sourceFilter = { mode: 'and', filters: [{ key: 'event_source_id', values: ['export/Report/report-id'] }], filterGroups: [] };
      mockAddFilter.mockReturnValueOnce(sourceFilter);
      const exportWork = { status: 'progress', messages: [], errors: [], updated_at: new Date().toISOString() };
      mockElPaginate.mockResolvedValue([
        { ...exportWork, internal_id: 'work-1', user_id: 'user-1' },
        { ...exportWork, internal_id: 'work-2', user_id: 'user-2' },
      ]);

      // paginatedForPathWithEnrichment gives no userId for bypass users
      const progressFiles = await loadExportWorksAsProgressFiles(context, ADMIN_USER, 'export/Report/report-id', { userId: undefined });

      expect(mockAddFilter).not.toHaveBeenCalledWith(null, 'user_id', expect.anything());
      expect(mockAddFilter).toHaveBeenNthCalledWith(1, null, 'event_source_id', 'export/Report/report-id');
      expect(progressFiles.map((file: { id: string }) => file.id)).toEqual(['work-1', 'work-2']);
      // Each progress file shows who requested the export
      expect(progressFiles.map((file: { metaData: { creator_id: string } }) => file.metaData.creator_id)).toEqual(['user-1', 'user-2']);
    });
  });
});
