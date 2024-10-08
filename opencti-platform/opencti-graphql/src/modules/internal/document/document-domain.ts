import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import moment from 'moment';
import { generateFileIndexId } from '../../../schema/identifier';
import { ENTITY_TYPE_INTERNAL_FILE } from '../../../schema/internalObject';
import { elAggregationCount, elCount, elDeleteInstances, elIndex } from '../../../database/engine';
import { INDEX_INTERNAL_OBJECTS, isEmptyField, READ_INDEX_INTERNAL_OBJECTS } from '../../../database/utils';
import { type EntityOptions, type FilterGroupWithNested, internalLoadById, listAllEntities, listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../../types/user';
import { type DomainFindById } from '../../../domain/domainTypes';
import type { BasicStoreEntityDocument } from './document-types';
import type { BasicStoreCommon } from '../../../types/store';
import { type File, FilterMode, FilterOperator, OrderingMode, State } from '../../../generated/graphql';
import { loadExportWorksAsProgressFiles } from '../../../domain/work';
import { elSearchFiles } from '../../../database/file-search';
import { SYSTEM_USER } from '../../../utils/access';
import { FROM_START_STR } from '../../../utils/format';
import { RELATION_OBJECT_MARKING } from '../../../schema/stixRefRelationship';
import { buildRefRelationKey } from '../../../schema/general';

export const SUPPORT_STORAGE_PATH = 'support';
export const IMPORT_STORAGE_PATH = 'import';
export const EXPORT_STORAGE_PATH = 'export';

export const DELETABLE_FILE_STATUSES = ['complete', 'timeout'];
export const UPLOAD_STATUS_VALUES = Object.values(State);
export const getIndexFromDate = async (context: AuthContext) => {
  const searchOptions = {
    first: 1,
    connectionFormat: false,
    highlight: false,
    orderBy: 'uploaded_at',
    orderMode: 'desc',
    excludeRemoved: false,
  };
  const lastIndexedFiles = await elSearchFiles(context, SYSTEM_USER, searchOptions);
  const lastIndexedFile = lastIndexedFiles?.length > 0 ? lastIndexedFiles[0] : null;
  return lastIndexedFile ? moment(lastIndexedFile.uploaded_at).toISOString() : FROM_START_STR;
};

export const buildFileDataForIndexing = (file: File) => {
  const standardId = generateFileIndexId(file.id);
  const fileData = R.dissoc('id', file);
  return {
    ...fileData,
    internal_id: file.id,
    standard_id: standardId,
    entity_type: ENTITY_TYPE_INTERNAL_FILE,
    [buildRefRelationKey(RELATION_OBJECT_MARKING)]: file.metaData?.file_markings ?? []
  };
};

export const indexFileToDocument = async (context: AuthContext, file: any) => {
  const data = buildFileDataForIndexing(file);
  const internalFile = await storeLoadById(context, SYSTEM_USER, data.internal_id, ENTITY_TYPE_INTERNAL_FILE);
  if (internalFile) {
    // update existing internalFile (if file has been saved in another index)
    return elIndex(internalFile._index, data);
  }
  return elIndex(INDEX_INTERNAL_OBJECTS, data);
};

export const deleteDocumentIndex = async (context: AuthContext, user: AuthUser, id: string) => {
  const internalFile = await storeLoadById(context, user, id, ENTITY_TYPE_INTERNAL_FILE);
  if (internalFile) {
    await elDeleteInstances([internalFile]);
  }
};

export const findById: DomainFindById<BasicStoreEntityDocument> = (context: AuthContext, user: AuthUser, fileId: string) => {
  return storeLoadById<BasicStoreEntityDocument>(context, user, fileId, ENTITY_TYPE_INTERNAL_FILE);
};

interface FilesOptions<T extends BasicStoreCommon> extends EntityOptions<T> {
  entity_id?: string
  entity_type?: string
  modifiedSince?: string | null
  notModifiedSince?: string | null
  prefixMimeTypes?: string[]
  maxFileSize?: number
  isPending?: boolean
  excludedPaths?: string[]
  orderBy?: string
  exact_path?: boolean
  orderMode?: OrderingMode
}

const buildFileFilters = (paths: string[], opts?: FilesOptions<BasicStoreEntityDocument>) => {
  const preparedPaths = paths.map((p) => (p.endsWith('/') ? p : `${p}/`));
  const filters: FilterGroupWithNested = {
    mode: FilterMode.And,
    filters: [{ key: ['internal_id'], values: preparedPaths, operator: FilterOperator.StartsWith }],
    filterGroups: opts?.filters ? [opts.filters] : [],
  };
  if (opts?.excludedPaths && opts?.excludedPaths.length > 0) {
    filters.filters.push({ key: ['internal_id'], values: opts.excludedPaths, mode: FilterMode.And, operator: FilterOperator.NotStartsWith });
  }
  if (opts?.prefixMimeTypes && opts?.prefixMimeTypes.length > 0) {
    filters.filters.push({ key: ['metaData.mimetype'], values: opts.prefixMimeTypes, operator: FilterOperator.StartsWith });
  }
  if (opts?.modifiedSince) {
    filters.filters.push({ key: ['lastModified'], values: [opts.modifiedSince], operator: FilterOperator.Gt });
  }
  if (opts?.notModifiedSince) {
    filters.filters.push({ key: ['lastModified'], values: [opts.notModifiedSince], operator: FilterOperator.Lt });
  }
  if (opts?.entity_id) {
    filters.filters.push({ key: ['metaData.entity_id'], values: [opts.entity_id] });
  } else if (opts?.exact_path) {
    filters.filters.push({ key: ['metaData.entity_id'], operator: FilterOperator.Nil, values: [] });
  }
  if (opts?.maxFileSize) {
    filters.filters.push({ key: ['size'], values: [String(opts.maxFileSize)], operator: FilterOperator.Lte });
  }
  return filters;
};

// List all available files with filtering capabilities
// Must only be used for internal purpose
export const allFilesForPaths = async (context: AuthContext, user: AuthUser, paths: string[], opts?: FilesOptions<BasicStoreEntityDocument>) => {
  const findOpts: EntityOptions<BasicStoreEntityDocument> = {
    filters: buildFileFilters(paths, opts),
    noFiltersChecking: true // No associated model
  };
  // Default ordering on lastModified starting from the oldest
  const orderOptions: any = {};
  if (isEmptyField(opts?.orderBy)) {
    orderOptions.orderBy = 'lastModified';
    orderOptions.orderMode = OrderingMode.Asc;
  }
  const listOptions = { ...opts, ...findOpts, ...orderOptions, indices: [READ_INDEX_INTERNAL_OBJECTS] };
  return listAllEntities<BasicStoreEntityDocument>(context, user, [ENTITY_TYPE_INTERNAL_FILE], listOptions);
};

// Count remaining files to index
export const allRemainingFilesCount = async (context: AuthContext, user: AuthUser, paths: string[], opts?: FilesOptions<BasicStoreEntityDocument>) => {
  const modifiedSince = await getIndexFromDate(context);
  const findOpts: EntityOptions<BasicStoreEntityDocument> = {
    filters: buildFileFilters(paths, { ...opts, modifiedSince }),
    noFiltersChecking: true // No associated model
  };
  const remainingOpts = { ...findOpts, types: [ENTITY_TYPE_INTERNAL_FILE] };
  return elCount(context, user, [READ_INDEX_INTERNAL_OBJECTS], remainingOpts);
};

export const allFilesMimeTypeDistribution = async (context: AuthContext, user: AuthUser, paths: string[], opts?: FilesOptions<BasicStoreEntityDocument>) => {
  const findOpts: EntityOptions<BasicStoreEntityDocument> = {
    filters: buildFileFilters(paths, opts),
    noFiltersChecking: true // No associated model
  };
  return elAggregationCount(context, user, READ_INDEX_INTERNAL_OBJECTS, {
    ...findOpts,
    types: [ENTITY_TYPE_INTERNAL_FILE],
    field: 'metaData.mimetype',
    weightField: 'size',
    normalizeLabel: false,
  });
};

// Get Files paginated with auto enrichment
// Images metadata for users
// In progress virtual files from export
export const paginatedForPathWithEnrichment = async (context: AuthContext, user: AuthUser, path: string, entity_id?: string, opts?: FilesOptions<BasicStoreEntityDocument>) => {
  const filterOpts = { ...opts, exact_path: isEmptyField(entity_id) };
  const findOpts: EntityOptions<BasicStoreEntityDocument> = {
    filters: buildFileFilters([path], filterOpts),
    noFiltersChecking: true // No associated model
  };
  const orderOptions: any = {};
  if (isEmptyField(opts?.orderBy)) {
    orderOptions.orderBy = 'lastModified';
    orderOptions.orderMode = OrderingMode.Desc;
  }
  const listOptions = { ...opts, entity_id, ...findOpts, ...orderOptions };

  const pagination = await listEntitiesPaginated<BasicStoreEntityDocument>(context, user, [ENTITY_TYPE_INTERNAL_FILE], listOptions);

  // region enrichment only possible for single path resolution
  // Enrich pagination for import images
  if (path.startsWith('import/') && entity_id) {
    const entity = await internalLoadById(context, user, entity_id, { type: opts?.entity_type });
    // Get files information to complete
    const internalFiles = entity?.x_opencti_files ?? [];
    if (internalFiles.length > 0) {
      const internalFilesMap = new Map(internalFiles.map((f) => [f.id, f]));
      for (let index = 0; index < pagination.edges.length; index += 1) {
        const edge = pagination.edges[index];
        const existingFile = internalFilesMap.get(edge.node.id);
        if (existingFile) {
          edge.node.metaData.order = existingFile.order;
          edge.node.metaData.description = existingFile.description;
          edge.node.metaData.inCarousel = existingFile.inCarousel;
        }
      }
    }
  }
  // Enrich pagination for ongoing exports
  if (path.startsWith('export/')) {
    const progressFiles = await loadExportWorksAsProgressFiles(context, user, path);
    pagination.edges = [...progressFiles.map((p: any) => ({ node: p, cursor: uuidv4() })), ...pagination.edges];
  }
  // endregion
  return pagination ?? [];
};
