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
import pjson from '../../../package.json';
import { createEntity, deleteElementById, listThings, paginateAllThings, patchAttribute, updateAttribute } from '../../database/middleware';
import { internalFindByIds, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { BUS_TOPICS } from '../../config/conf';
import { delEditContext, notify, setEditContext } from '../../database/redis';
import { ENTITY_TYPE_WORKSPACE } from './workspace-types';
import { FunctionalError } from '../../config/errors';
import { getUserAccessRight, isValidMemberAccessRight, MEMBER_ACCESS_RIGHT_ADMIN } from '../../utils/access';
import { publishUserAction } from '../../listener/UserActionListener';
import { containsValidAdmin } from '../../utils/authorizedMembers';
import { elFindByIds } from '../../database/engine';
import { buildPagination, fromBase64, isEmptyField, isNotEmptyField, READ_DATA_INDICES_WITHOUT_INTERNAL, toBase64 } from '../../database/utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { extractContentFrom } from '../../utils/fileToContent';
import { isInternalId, isStixId } from '../../schema/schemaUtils';
import { INSTANCE_REGARDING_OF } from '../../utils/filtering/filtering-constants';
export const findById = (context, user, workspaceId) => {
    return storeLoadById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE);
};
export const findAll = (context, user, args) => {
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_WORKSPACE], args);
};
export const editAuthorizedMembers = (context, user, workspaceId, input) => __awaiter(void 0, void 0, void 0, function* () {
    // validate input (validate access right) and remove duplicates
    const filteredInput = input.filter((value, index, array) => {
        return (isValidMemberAccessRight(value.access_right)
            && array.findIndex((e) => e.id === value.id) === index);
    });
    const hasValidAdmin = yield containsValidAdmin(context, filteredInput, ['EXPLORE_EXUPDATE_EXDELETE']);
    if (!hasValidAdmin) {
        throw FunctionalError('Workspace should have at least one admin');
    }
    const authorizedMembersInput = filteredInput.map((e) => {
        return { id: e.id, access_right: e.access_right };
    });
    const patch = { authorized_members: authorizedMembersInput };
    const { element } = yield patchAttribute(context, user, workspaceId, ENTITY_TYPE_WORKSPACE, patch);
    return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, element, user);
});
export const getCurrentUserAccessRight = (context, user, workspace) => __awaiter(void 0, void 0, void 0, function* () {
    return getUserAccessRight(user, workspace);
});
export const getOwnerId = (workspace) => {
    return Array.isArray(workspace.creator_id) && workspace.creator_id.length > 0
        ? workspace.creator_id.at(0)
        : workspace.creator_id;
};
export const objects = (context, user, { investigated_entities_ids }, args) => __awaiter(void 0, void 0, void 0, function* () {
    if (isEmptyField(investigated_entities_ids)) {
        return buildPagination(0, null, [], 0);
    }
    const filters = addFilter(args.filters, 'internal_id', investigated_entities_ids);
    const finalArgs = Object.assign(Object.assign({}, args), { filters });
    if (args.all) {
        return paginateAllThings(context, user, args.types, finalArgs);
    }
    return listThings(context, user, args.types, finalArgs);
});
const checkInvestigatedEntitiesInputs = (context, user, inputs) => __awaiter(void 0, void 0, void 0, function* () {
    const addedOrReplacedInvestigatedEntitiesIds = inputs
        .filter(({ key, operation }) => key === 'investigated_entities_ids'
        && (operation === 'add' || operation === 'replace'))
        .flatMap(({ value }) => value);
    const opts = { indices: READ_DATA_INDICES_WITHOUT_INTERNAL };
    const entities = (yield elFindByIds(context, user, addedOrReplacedInvestigatedEntitiesIds, opts));
    const missingEntitiesIds = R.difference(addedOrReplacedInvestigatedEntitiesIds, entities.map((entity) => entity.id));
    if (missingEntitiesIds.length > 0) {
        throw FunctionalError('Invalid ids specified', { ids: missingEntitiesIds });
    }
});
const initializeAuthorizedMembers = (authorizedMembers, user) => {
    const initializedAuthorizedMembers = authorizedMembers !== null && authorizedMembers !== void 0 ? authorizedMembers : [];
    if (!(authorizedMembers === null || authorizedMembers === void 0 ? void 0 : authorizedMembers.some((e) => e.id === user.id))) {
        // add creator to authorized_members on creation
        initializedAuthorizedMembers.push({
            id: user.id,
            access_right: MEMBER_ACCESS_RIGHT_ADMIN,
        });
    }
    return initializedAuthorizedMembers;
};
export const addWorkspace = (context, user, input) => __awaiter(void 0, void 0, void 0, function* () {
    const authorizedMembers = initializeAuthorizedMembers(input.authorized_members, user);
    const workspaceToCreate = Object.assign(Object.assign({}, input), { authorized_members: authorizedMembers });
    const created = yield createEntity(context, user, workspaceToCreate, ENTITY_TYPE_WORKSPACE);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'create',
        event_access: 'extended',
        message: `creates ${created.type} workspace \`${created.name}\``,
        context_data: { id: created.id, entity_type: ENTITY_TYPE_WORKSPACE, input },
    });
    return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, created, user);
});
export const workspaceDelete = (context, user, workspaceId) => __awaiter(void 0, void 0, void 0, function* () {
    const deleted = yield deleteElementById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'delete',
        event_access: 'administration',
        message: `deletes ${deleted.type} workspace \`${deleted.name}\``,
        context_data: {
            id: workspaceId,
            entity_type: ENTITY_TYPE_WORKSPACE,
            input: deleted,
        },
    });
    return workspaceId;
});
export const workspaceEditField = (context, user, workspaceId, inputs) => __awaiter(void 0, void 0, void 0, function* () {
    yield checkInvestigatedEntitiesInputs(context, user, inputs);
    const { element } = yield updateAttribute(context, user, workspaceId, ENTITY_TYPE_WORKSPACE, inputs);
    return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, element, user);
});
export const workspaceCleanContext = (context, user, workspaceId) => __awaiter(void 0, void 0, void 0, function* () {
    yield delEditContext(user, workspaceId);
    return storeLoadById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE).then((userToReturn) => {
        return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, userToReturn, user);
    });
});
export const workspaceEditContext = (context, user, workspaceId, input) => __awaiter(void 0, void 0, void 0, function* () {
    yield setEditContext(user, workspaceId, input);
    return storeLoadById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE).then((workspaceToReturn) => notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, workspaceToReturn, user));
});
const MINIMAL_COMPATIBLE_VERSION = '5.12.16';
const configurationImportTypeValidation = new Map();
configurationImportTypeValidation.set('dashboard', 'Invalid type. Please import OpenCTI dashboard-type only');
configurationImportTypeValidation.set('widget', 'Invalid type. Please import OpenCTI widget-type only');
export const checkConfigurationImport = (type, parsedData) => {
    if (configurationImportTypeValidation.has(type) && parsedData.type !== type) {
        throw FunctionalError(configurationImportTypeValidation.get(type), {
            reason: parsedData.type,
        });
    }
    const isCompatibleOpenCtiVersion = (openCtiVersion) => {
        const [major, minor, patch] = openCtiVersion.split('.').map((number) => parseInt(number, 10));
        const [openCtiMajor, openCtiMinor, openCtiPatch] = MINIMAL_COMPATIBLE_VERSION.split('.').map((number) => parseInt(number, 10));
        return major >= openCtiMajor && minor >= openCtiMinor && patch >= openCtiPatch;
    };
    if (!isCompatibleOpenCtiVersion(parsedData.openCTI_version)) {
        throw FunctionalError(`Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: ${MINIMAL_COMPATIBLE_VERSION}`, { reason: parsedData.openCTI_version });
    }
};
// region workspace ids converter
// Export => Dashboard filter ids must be converted to standard id
// Import => Dashboards filter ids must be converted back to internal id
const toKeys = (k) => (Array.isArray(k) ? k : [k]);
const extractFiltersIds = (filter, from) => {
    const internalIds = [];
    filter.filters.forEach((f) => {
        var _a, _b;
        let innerValues = f.values;
        if (toKeys(f.key).includes(INSTANCE_REGARDING_OF)) {
            innerValues = (_b = (_a = innerValues.find((v) => toKeys(v.key).includes('id'))) === null || _a === void 0 ? void 0 : _a.values) !== null && _b !== void 0 ? _b : [];
        }
        const ids = innerValues.filter((value) => {
            if (from === 'internal')
                return isInternalId(value);
            return isStixId(value);
        });
        internalIds.push(...ids);
    });
    filter.filterGroups.forEach((group) => {
        const groupIds = extractFiltersIds(group, from);
        internalIds.push(...groupIds);
    });
    return R.uniq(internalIds);
};
const filterValuesRemap = (filter, resolvedMap, from) => {
    return filter.values.map((value) => {
        var _a, _b, _c, _d;
        if (from === 'internal' && isInternalId(value)) {
            return (_b = (_a = resolvedMap[value]) === null || _a === void 0 ? void 0 : _a.standard_id) !== null && _b !== void 0 ? _b : value;
        }
        if (from === 'stix' && isStixId(value)) {
            return (_d = (_c = resolvedMap[value]) === null || _c === void 0 ? void 0 : _c.internal_id) !== null && _d !== void 0 ? _d : value;
        }
        return value;
    });
};
const replaceFiltersIds = (filter, resolvedMap, from) => {
    filter.filters.forEach((f) => {
        // Explicit reassign working by references
        if (toKeys(f.key).includes(INSTANCE_REGARDING_OF)) {
            const regardingOfValues = [];
            const idInnerFilter = f.values.find((v) => toKeys(v.key).includes('id'));
            if (idInnerFilter) { // Id is not mandatory
                idInnerFilter.values = filterValuesRemap(idInnerFilter, resolvedMap, from);
                regardingOfValues.push(idInnerFilter);
            }
            const typeInnerFilter = f.values.find((v) => toKeys(v.key).includes('type'));
            if (typeInnerFilter) { // Type is not mandatory
                regardingOfValues.push(typeInnerFilter);
            }
            // eslint-disable-next-line no-param-reassign
            f.values = regardingOfValues;
        }
        else {
            // eslint-disable-next-line no-param-reassign
            f.values = filterValuesRemap(f, resolvedMap, from);
        }
    });
    filter.filterGroups.forEach((group) => {
        replaceFiltersIds(group, resolvedMap, from);
    });
};
// For now, this function is only useful for workspace dashboards
const convertWidgetsIds = (context, user, widgetDefinitions, from) => __awaiter(void 0, void 0, void 0, function* () {
    // First iteration to resolve all ids to translate
    const resolvingIds = [];
    widgetDefinitions.forEach((widgetDefinition) => {
        widgetDefinition.dataSelection.forEach((selection) => {
            if (isNotEmptyField(selection.filters)) {
                const filterIds = extractFiltersIds(selection.filters, from);
                resolvingIds.push(...filterIds);
            }
            if (isNotEmptyField(selection.dynamicFrom)) {
                const dynamicFromIds = extractFiltersIds(selection.dynamicFrom, from);
                resolvingIds.push(...dynamicFromIds);
            }
            if (isNotEmptyField(selection.dynamicTo)) {
                const dynamicToIds = extractFiltersIds(selection.dynamicTo, from);
                resolvingIds.push(...dynamicToIds);
            }
        });
    });
    // Resolve then second iteration to replace the ids
    const resolveOpts = { baseData: true, toMap: true, mapWithAllIds: true };
    const resolvedMap = yield internalFindByIds(context, user, resolvingIds, resolveOpts);
    const idsMap = resolvedMap;
    widgetDefinitions.forEach((widgetDefinition) => {
        widgetDefinition.dataSelection.forEach((selection) => {
            if (isNotEmptyField(selection.filters)) {
                replaceFiltersIds(selection.filters, idsMap, from);
            }
            if (isNotEmptyField(selection.dynamicFrom)) {
                replaceFiltersIds(selection.dynamicFrom, idsMap, from);
            }
            if (isNotEmptyField(selection.dynamicTo)) {
                replaceFiltersIds(selection.dynamicTo, idsMap, from);
            }
        });
    });
});
const convertWorkspaceManifestIds = (context, user, manifest, from) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    const parsedManifest = JSON.parse((_a = fromBase64(manifest)) !== null && _a !== void 0 ? _a : '{}');
    // Regeneration for dashboards
    if (parsedManifest && isNotEmptyField(parsedManifest.widgets)) {
        const { widgets } = parsedManifest;
        const widgetDefinitions = Object.values(widgets);
        yield convertWidgetsIds(context, user, widgetDefinitions, from);
        return toBase64(JSON.stringify(parsedManifest));
    }
    return manifest;
});
// endregion
export const generateWorkspaceExportConfiguration = (context, user, workspace) => __awaiter(void 0, void 0, void 0, function* () {
    if (workspace.type !== 'dashboard') {
        throw FunctionalError('WORKSPACE_EXPORT_INCOMPATIBLE_TYPE', { type: workspace.type });
    }
    const generatedManifest = yield convertWorkspaceManifestIds(context, user, workspace.manifest, 'internal');
    const exportConfigration = {
        openCTI_version: pjson.version,
        type: 'dashboard',
        configuration: {
            name: workspace.name,
            manifest: generatedManifest
        },
    };
    return JSON.stringify(exportConfigration);
});
export const generateWidgetExportConfiguration = (context, user, workspace, widgetId) => __awaiter(void 0, void 0, void 0, function* () {
    var _b;
    if (workspace.type !== 'dashboard') {
        throw FunctionalError('WORKSPACE_EXPORT_INCOMPATIBLE_TYPE', { type: workspace.type });
    }
    const parsedManifest = JSON.parse((_b = fromBase64(workspace.manifest)) !== null && _b !== void 0 ? _b : '{}');
    if (parsedManifest && isNotEmptyField(parsedManifest.widgets) && parsedManifest.widgets[widgetId]) {
        const widgetDefinition = parsedManifest.widgets[widgetId];
        delete widgetDefinition.id; // Remove current widget id
        yield convertWidgetsIds(context, user, [widgetDefinition], 'internal');
        const exportConfigration = {
            openCTI_version: pjson.version,
            type: 'widget',
            configuration: toBase64(JSON.stringify(widgetDefinition))
        };
        return JSON.stringify(exportConfigration);
    }
    throw FunctionalError('WIDGET_EXPORT_NOT_FOUND', { workspace: workspace.id, widget: widgetId });
});
export const workspaceImportConfiguration = (context, user, file) => __awaiter(void 0, void 0, void 0, function* () {
    const parsedData = yield extractContentFrom(file);
    checkConfigurationImport('dashboard', parsedData);
    const authorizedMembers = initializeAuthorizedMembers([], user);
    const { manifest } = parsedData.configuration;
    // Manifest ids must be rewritten for filters
    const generatedManifest = yield convertWorkspaceManifestIds(context, user, manifest, 'stix');
    const mappedData = {
        type: parsedData.type,
        openCTI_version: parsedData.openCTI_version,
        name: parsedData.configuration.name,
        manifest: generatedManifest,
        authorized_members: authorizedMembers,
    };
    const importWorkspaceCreation = yield createEntity(context, user, mappedData, ENTITY_TYPE_WORKSPACE);
    const workspaceId = importWorkspaceCreation.id;
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'create',
        event_access: 'extended',
        message: `import ${importWorkspaceCreation.name} workspace`,
        context_data: {
            id: workspaceId,
            entity_type: ENTITY_TYPE_WORKSPACE,
            input: importWorkspaceCreation,
        },
    });
    yield notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, importWorkspaceCreation, user);
    return workspaceId;
});
export const duplicateWorkspace = (context, user, input) => __awaiter(void 0, void 0, void 0, function* () {
    const authorizedMembers = initializeAuthorizedMembers([], user);
    const workspaceToCreate = Object.assign(Object.assign({}, input), { authorized_members: authorizedMembers });
    const created = yield createEntity(context, user, workspaceToCreate, ENTITY_TYPE_WORKSPACE);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'create',
        event_access: 'extended',
        message: `creates ${created.type} workspace \`${created.name}\` from custom-named duplication`,
        context_data: { id: created.id, entity_type: ENTITY_TYPE_WORKSPACE, input },
    });
    return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, created, user);
});
export const workspaceImportWidgetConfiguration = (context, user, workspaceId, input) => __awaiter(void 0, void 0, void 0, function* () {
    const parsedData = yield extractContentFrom(input.file);
    checkConfigurationImport('widget', parsedData);
    const widgetDefinition = JSON.parse(fromBase64(parsedData.configuration) || '{}');
    yield convertWidgetsIds(context, user, [widgetDefinition], 'stix');
    const mappedData = {
        type: parsedData.type,
        openCTI_version: parsedData.openCTI_version,
        widget: widgetDefinition,
    };
    const importedWidgetId = uuidv4();
    const dashboardManifestObjects = JSON.parse(fromBase64(input.dashboardManifest) || '{}');
    const updatedObjects = Object.assign(Object.assign({}, dashboardManifestObjects), { widgets: Object.assign(Object.assign({}, dashboardManifestObjects.widgets), { [`${importedWidgetId}`]: Object.assign({ id: importedWidgetId }, mappedData.widget) }) });
    const updatedManifest = toBase64(JSON.stringify(updatedObjects));
    const { element } = yield updateAttribute(context, user, workspaceId, ENTITY_TYPE_WORKSPACE, [{ key: 'manifest', value: [updatedManifest] }]);
    yield publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'create',
        event_access: 'extended',
        message: `import widget (id : ${importedWidgetId}) in workspace (id : ${workspaceId})`,
        context_data: {
            id: workspaceId,
            entity_type: ENTITY_TYPE_WORKSPACE,
            input: element,
        },
    });
    return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, element, user);
});
