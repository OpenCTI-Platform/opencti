var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import moment from 'moment';
import { generateFileIndexId } from '../../../schema/identifier';
import { ENTITY_TYPE_INTERNAL_FILE } from '../../../schema/internalObject';
import { elCount, elDeleteInstances, elIndex } from '../../../database/engine';
import { INDEX_INTERNAL_OBJECTS, isEmptyField, isNotEmptyField, READ_INDEX_INTERNAL_OBJECTS } from '../../../database/utils';
import { internalLoadById, listAllEntities, listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import {} from '../../../domain/domainTypes';
import { FilterMode, FilterOperator, OrderingMode } from '../../../generated/graphql';
import { loadExportWorksAsProgressFiles } from '../../../domain/work';
import { elSearchFiles } from '../../../database/file-search';
import { SYSTEM_USER } from '../../../utils/access';
import { FROM_START_STR } from '../../../utils/format';
import { buildContextDataForFile, publishUserAction } from '../../../listener/UserActionListener';
import { ForbiddenAccess } from '../../../config/errors';
export const getIndexFromDate = (context) => __awaiter(void 0, void 0, void 0, function* () {
    const searchOptions = {
        first: 1,
        connectionFormat: false,
        highlight: false,
        orderBy: 'uploaded_at',
        orderMode: 'desc',
    };
    const lastIndexedFiles = yield elSearchFiles(context, SYSTEM_USER, searchOptions);
    const lastIndexedFile = (lastIndexedFiles === null || lastIndexedFiles === void 0 ? void 0 : lastIndexedFiles.length) > 0 ? lastIndexedFiles[0] : null;
    return lastIndexedFile ? moment(lastIndexedFile.uploaded_at).toISOString() : FROM_START_STR;
});
export const buildFileDataForIndexing = (file) => {
    const standardId = generateFileIndexId(file.id);
    const fileData = R.dissoc('id', file);
    return Object.assign(Object.assign({}, fileData), { internal_id: file.id, standard_id: standardId, entity_type: ENTITY_TYPE_INTERNAL_FILE });
};
export const indexFileToDocument = (file) => __awaiter(void 0, void 0, void 0, function* () {
    const data = buildFileDataForIndexing(file);
    yield elIndex(INDEX_INTERNAL_OBJECTS, data);
});
export const deleteDocumentIndex = (context, user, id) => __awaiter(void 0, void 0, void 0, function* () {
    const internalFile = yield storeLoadById(context, user, id, ENTITY_TYPE_INTERNAL_FILE);
    if (internalFile) {
        yield elDeleteInstances([internalFile]);
    }
});
export const findById = (context, user, fileId) => {
    return storeLoadById(context, user, fileId, ENTITY_TYPE_INTERNAL_FILE);
};
const buildFileFilters = (paths, opts) => {
    const filters = {
        mode: FilterMode.And,
        filters: [{ key: ['internal_id'], values: paths, operator: FilterOperator.StartsWith }],
        filterGroups: []
    };
    if ((opts === null || opts === void 0 ? void 0 : opts.excludedPaths) && (opts === null || opts === void 0 ? void 0 : opts.excludedPaths.length) > 0) {
        filters.filters.push({ key: ['internal_id'], values: opts.excludedPaths, mode: FilterMode.And, operator: FilterOperator.NotStartsWith });
    }
    if ((opts === null || opts === void 0 ? void 0 : opts.prefixMimeTypes) && (opts === null || opts === void 0 ? void 0 : opts.prefixMimeTypes.length) > 0) {
        filters.filters.push({ key: ['metaData.mimetype'], values: opts.prefixMimeTypes, operator: FilterOperator.StartsWith });
    }
    if (opts === null || opts === void 0 ? void 0 : opts.modifiedSince) {
        filters.filters.push({ key: ['lastModified'], values: [opts.modifiedSince], operator: FilterOperator.Gt });
    }
    if (opts === null || opts === void 0 ? void 0 : opts.entity_id) {
        filters.filters.push({ key: ['metaData.entity_id'], values: [opts.entity_id] });
    }
    if (opts === null || opts === void 0 ? void 0 : opts.maxFileSize) {
        filters.filters.push({ key: ['size'], values: [String(opts.maxFileSize)], operator: FilterOperator.Lte });
    }
    return filters;
};
// List all available files with filtering capabilities
// Must only be used for internal purpose
export const allFilesForPaths = (context, user, paths, opts) => __awaiter(void 0, void 0, void 0, function* () {
    const findOpts = {
        filters: buildFileFilters(paths, opts),
        noFiltersChecking: true // No associated model
    };
    // Default ordering on lastModified starting from the oldest
    const orderOptions = {};
    if (isEmptyField(opts === null || opts === void 0 ? void 0 : opts.orderBy)) {
        orderOptions.orderBy = 'lastModified';
        orderOptions.orderMode = OrderingMode.Asc;
    }
    const listOptions = Object.assign(Object.assign(Object.assign(Object.assign({}, opts), findOpts), orderOptions), { indices: [READ_INDEX_INTERNAL_OBJECTS] });
    return listAllEntities(context, user, [ENTITY_TYPE_INTERNAL_FILE], listOptions);
});
// Count remaining files to index
export const allRemainingFilesCount = (context, user, paths, opts) => __awaiter(void 0, void 0, void 0, function* () {
    const modifiedSince = yield getIndexFromDate(context);
    const findOpts = {
        filters: buildFileFilters(paths, Object.assign(Object.assign({}, opts), { modifiedSince })),
        noFiltersChecking: true // No associated model
    };
    const remainingOpts = Object.assign(Object.assign({}, findOpts), { types: [ENTITY_TYPE_INTERNAL_FILE] });
    return elCount(context, user, [READ_INDEX_INTERNAL_OBJECTS], remainingOpts);
});
export const checkFileAccess = (context, user, scope, { entity_id, filename, id }) => __awaiter(void 0, void 0, void 0, function* () {
    if (isEmptyField(entity_id)) {
        return true;
    }
    const userInstancePromise = internalLoadById(context, user, entity_id);
    const systemInstancePromise = internalLoadById(context, SYSTEM_USER, entity_id);
    const [instance, systemInstance] = yield Promise.all([userInstancePromise, systemInstancePromise]);
    if (isEmptyField(instance)) {
        if (isNotEmptyField(systemInstance)) {
            const data = buildContextDataForFile(systemInstance, id, filename);
            yield publishUserAction({
                user,
                event_type: 'file',
                event_scope: scope,
                event_access: 'extended',
                status: 'error',
                context_data: data
            });
        }
        throw ForbiddenAccess('Access to this file is restricted', { id: entity_id, file: id });
    }
    return true;
});
// Get Files paginated with auto enrichment
// Images metadata for users
// In progress virtual files from export
export const paginatedForPathWithEnrichment = (context, user, path, entity_id, opts) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    const findOpts = {
        filters: buildFileFilters([path], opts),
        noFiltersChecking: true // No associated model
    };
    const orderOptions = {};
    if (isEmptyField(opts === null || opts === void 0 ? void 0 : opts.orderBy)) {
        orderOptions.orderBy = 'lastModified';
        orderOptions.orderMode = OrderingMode.Desc;
    }
    const listOptions = Object.assign(Object.assign(Object.assign(Object.assign({}, opts), { entity_id }), findOpts), orderOptions);
    yield checkFileAccess(context, user, 'read', { entity_id, id: path, filename: '' });
    const pagination = yield listEntitiesPaginated(context, SYSTEM_USER, [ENTITY_TYPE_INTERNAL_FILE], listOptions);
    // region enrichment only possible for single path resolution
    // Enrich pagination for import images
    if (path.startsWith('import/') && entity_id) {
        const entity = yield internalLoadById(context, user, entity_id, { type: opts === null || opts === void 0 ? void 0 : opts.entity_type });
        // Get files information to complete
        const internalFiles = (_a = entity === null || entity === void 0 ? void 0 : entity.x_opencti_files) !== null && _a !== void 0 ? _a : [];
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
        const progressFiles = yield loadExportWorksAsProgressFiles(context, user, path);
        pagination.edges = [...progressFiles.map((p) => ({ node: p, cursor: uuidv4() })), ...pagination.edges];
    }
    // endregion
    return pagination;
});
