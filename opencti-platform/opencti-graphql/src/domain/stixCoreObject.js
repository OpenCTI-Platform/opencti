import * as R from 'ramda';
import { buildRestrictedEntity, createEntity, createRelationRaw, deleteElementById, distributionEntities, storeLoadByIdWithRefs, timeSeriesEntities } from '../database/middleware';
import { internalFindByIds, internalLoadById, listEntitiesPaginated, listEntitiesThroughRelationsPaginated, storeLoadById } from '../database/middleware-loader';
import { findAll as relationFindAll } from './stixCoreRelationship';
import { delEditContext, notify, setEditContext, storeUpdateEvent } from '../database/redis';
import conf, { BUS_TOPICS, logApp } from '../config/conf';
import { ForbiddenAccess, FunctionalError, LockTimeoutError, ResourceNotFoundError, TYPE_LOCK_ERROR, UnsupportedError } from '../config/errors';
import { isStixCoreObject, stixCoreObjectOptions } from '../schema/stixCoreObject';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  buildRefRelationKey,
  CONNECTOR_INTERNAL_ANALYSIS,
  CONNECTOR_INTERNAL_ENRICHMENT,
  ENTITY_TYPE_CONTAINER,
  INPUT_EXTERNAL_REFS,
  INPUT_MARKINGS,
  REL_INDEX_PREFIX
} from '../schema/general';
import { RELATION_CREATED_BY, RELATION_EXTERNAL_REFERENCE, RELATION_OBJECT, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import {
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  isStixDomainObjectContainer
} from '../schema/stixDomainObject';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { createWork, worksForSource, workToExportFile } from './work';
import { pushToConnector } from '../database/rabbitmq';
import { minutesAgo, monthsAgo, now, utcDate } from '../utils/format';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { deleteFile, getFileContent, loadFile, storeFileConverter } from '../database/file-storage';
import { findById as documentFindById, paginatedForPathWithEnrichment } from '../modules/internal/document/document-domain';
import { elCount, elFindByIds, elUpdateElement } from '../database/engine';
import { generateStandardId, getInstanceIds } from '../schema/identifier';
import { askEntityExport, askListExport, exportTransformFilters } from './stix';
import { isEmptyField, isNotEmptyField, READ_ENTITIES_INDICES, READ_INDEX_INFERRED_ENTITIES } from '../database/utils';
import { ENTITY_TYPE_CONTAINER_CASE } from '../modules/case/case-types';
import { getEntitySettingFromCache } from '../modules/entitySetting/entitySetting-utils';
import { stixObjectOrRelationshipAddRefRelation, stixObjectOrRelationshipAddRefRelations, stixObjectOrRelationshipDeleteRefRelation } from './stixObjectOrStixRelationship';
import { buildContextDataForFile, completeContextDataForEntity, publishUserAction } from '../listener/UserActionListener';
import { extractEntityRepresentativeName } from '../database/entity-representative';
import { addFilter, findFiltersFromKey } from '../utils/filtering/filtering-utils';
import { INSTANCE_REGARDING_OF } from '../utils/filtering/filtering-constants';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../modules/grouping/grouping-types';
import { getEntitiesMapFromCache } from '../database/cache';
import { isBypassUser, isUserCanAccessStoreElement, SYSTEM_USER, validateUserAccessOperation } from '../utils/access';
import { uploadToStorage } from '../database/file-storage-helper';
import { connectorsForAnalysis } from '../database/repository';
import { getDraftContext } from '../utils/draftContext';
import { FilterOperator } from '../generated/graphql';
import {
  getContainersStats,
  getHistory,
  getIndicatorsStats,
  getTargetingStats,
  getTopThreats,
  getTopVictims,
  getVictimologyStats,
  systemPrompt
} from '../utils/ai/dataResolutionHelpers';
import { queryAi } from '../database/ai-llm';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../modules/threatActorIndividual/threatActorIndividual-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { ENTITY_TYPE_EVENT } from '../modules/event/event-types';
import { checkEnterpriseEdition } from '../enterprise-edition/ee';
import { AI_BUS } from '../modules/ai/ai-types';
import { lockResources } from '../lock/master-lock';

const AI_INSIGHTS_REFRESH_TIMEOUT = conf.get('ai:insights_refresh_timeout');
const aiResponseCache = {};
const threats = [ENTITY_TYPE_THREAT_ACTOR_GROUP, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_MALWARE];
// const arsenal = [ENTITY_TYPE_TOOL, ENTITY_TYPE_ATTACK_PATTERN];
const victims = [
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_EVENT
];

const extractStixCoreObjectTypesFromArgs = (args) => {
  let types = [];
  if (isNotEmptyField(args.types)) {
    types = args.types.filter((type) => isStixCoreObject(type));
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CORE_OBJECT);
  }
  return types;
};

export const findAll = async (context, user, args) => {
  const types = extractStixCoreObjectTypesFromArgs(args);
  if (args.globalSearch) {
    const contextData = {
      input: R.omit(['search'], args)
    };
    if (args.search && args.search.length > 0) {
      contextData.search = args.search;
    }
    await publishUserAction({
      user,
      event_type: 'command',
      event_scope: 'search',
      event_access: 'extended',
      context_data: contextData,
    });
  }
  return listEntitiesPaginated(context, user, types, args);
};

export const findAllAuthMemberRestricted = async (context, user, args) => {
  if (!isBypassUser(user)) {
    throw ForbiddenAccess();
  }
  const types = extractStixCoreObjectTypesFromArgs(args);
  const filters = addFilter(args.filters, 'authorized_members.id', [], FilterOperator.NotNil);
  const finalArgs = {
    ...args,
    includeAuthorities: true,
    filters
  };

  return listEntitiesPaginated(context, user, types, finalArgs);
};

export const findById = async (context, user, stixCoreObjectId) => {
  return storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
};

export const batchInternalRels = async (context, user, elements, opts = {}) => {
  const relIds = new Set();
  const relTypes = new Set();
  for (let index = 0; index < elements.length; index += 1) {
    const { element, definition } = elements[index];
    if (isNotEmptyField(element[definition.databaseName])) {
      const ids = Array.isArray(element[definition.databaseName]) ? element[definition.databaseName] : [element[definition.databaseName]];
      ids.filter((id) => isNotEmptyField(id)).forEach(relIds.add, relIds);
      definition.toTypes.forEach(relTypes.add, relTypes);
    }
  }
  // Get all rel resolutions with system user
  // The visibility will be restricted in the data preparation
  const resolvedElements = await internalFindByIds(context, SYSTEM_USER, Array.from(relIds), { type: Array.from(relTypes), toMap: true });
  return await Promise.all(elements.map(async ({ element, definition }) => {
    const relId = element[definition.databaseName];
    if (definition.multiple) {
      const relElements = await Promise.all((relId ?? []).map(async (id) => {
        const resolve = resolvedElements[id];
        // If resolution is empty the database is inconsistent, an error must be thrown
        if (isEmptyField(resolve)) {
          throw UnsupportedError('Invalid loading of batched elements', { ids: relId });
        }
        // If user have correct access right, return the element
        if (await isUserCanAccessStoreElement(context, user, resolve)) {
          return resolve;
        }
        // If access is not possible, return a restricted entity
        return buildRestrictedEntity(resolve);
      }));
      // Return sorted elements if needed
      if (opts.sortBy) {
        return R.sortWith([R.ascend(R.prop(opts.sortBy))])(relElements);
      }
      return relElements;
    }
    if (relId) {
      const resolve = resolvedElements[relId];
      // If resolution is empty the database is inconsistent, an error must be thrown
      if (isEmptyField(resolve)) {
        throw UnsupportedError('Invalid loading of batched element', { id: relId });
      }
      // If user have correct access right, return the element
      if (await isUserCanAccessStoreElement(context, user, resolve)) {
        return resolve;
      }
      // If access is not possible, return a restricted entity
      return buildRestrictedEntity(resolve);
    }
    return undefined;
  }));
};

export const batchMarkingDefinitions = async (context, user, stixCoreObjects) => {
  const markingsFromCache = await getEntitiesMapFromCache(context, user, ENTITY_TYPE_MARKING_DEFINITION);
  return stixCoreObjects.map((s) => {
    const markings = (s[RELATION_OBJECT_MARKING] ?? []).map((id) => markingsFromCache.get(id));
    return R.sortWith([
      R.ascend(R.propOr('TLP', 'definition_type')),
      R.descend(R.propOr(0, 'x_opencti_order')),
    ])(markings);
  });
};

export const containersPaginated = async (context, user, stixCoreObjectId, opts) => {
  const { entityTypes } = opts;
  const finalEntityTypes = entityTypes ?? [ENTITY_TYPE_CONTAINER];
  if (!finalEntityTypes.every((t) => isStixDomainObjectContainer(t))) {
    throw FunctionalError(`Only ${ENTITY_TYPE_CONTAINER} can be query through this method.`);
  }
  return listEntitiesThroughRelationsPaginated(context, user, stixCoreObjectId, RELATION_OBJECT, finalEntityTypes, true, opts);
};

export const reportsPaginated = async (context, user, stixCoreObjectId, opts) => {
  return listEntitiesThroughRelationsPaginated(context, user, stixCoreObjectId, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_REPORT, true, opts);
};

export const groupingsPaginated = async (context, user, stixCoreObjectId, opts) => {
  return listEntitiesThroughRelationsPaginated(context, user, stixCoreObjectId, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_GROUPING, true, opts);
};

export const casesPaginated = async (context, user, stixCoreObjectId, opts) => {
  return listEntitiesThroughRelationsPaginated(context, user, stixCoreObjectId, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_CASE, true, opts);
};

export const notesPaginated = async (context, user, stixCoreObjectId, opts) => {
  return listEntitiesThroughRelationsPaginated(context, user, stixCoreObjectId, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_NOTE, true, opts);
};

export const opinionsPaginated = async (context, user, stixCoreObjectId, opts) => {
  return listEntitiesThroughRelationsPaginated(context, user, stixCoreObjectId, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_OPINION, true, opts);
};

export const observedDataPaginated = async (context, user, stixCoreObjectId, opts) => {
  return listEntitiesThroughRelationsPaginated(context, user, stixCoreObjectId, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_OBSERVED_DATA, true, opts);
};

export const externalReferencesPaginated = async (context, user, stixCoreObjectId, opts) => {
  return listEntitiesThroughRelationsPaginated(context, user, stixCoreObjectId, RELATION_EXTERNAL_REFERENCE, ENTITY_TYPE_EXTERNAL_REFERENCE, false, opts);
};

export const stixCoreRelationships = (context, user, stixCoreObjectId, args) => {
  const finalArgs = R.assoc('fromOrToId', stixCoreObjectId, args);
  return relationFindAll(context, user, finalArgs);
};

// region relation ref
export const stixCoreObjectAddRelation = async (context, user, stixCoreObjectId, input) => {
  return stixObjectOrRelationshipAddRefRelation(context, user, stixCoreObjectId, input, ABSTRACT_STIX_CORE_OBJECT);
};
export const stixCoreObjectAddRelations = async (context, user, stixCoreObjectId, input, opts = {}) => {
  return stixObjectOrRelationshipAddRefRelations(context, user, stixCoreObjectId, input, ABSTRACT_STIX_CORE_OBJECT, opts);
};
export const stixCoreObjectDeleteRelation = async (context, user, stixCoreObjectId, toId, relationshipType, opts = {}) => {
  return stixObjectOrRelationshipDeleteRefRelation(context, user, stixCoreObjectId, toId, relationshipType, ABSTRACT_STIX_CORE_OBJECT, opts);
};
// endregion

export const stixCoreObjectDelete = async (context, user, stixCoreObjectId) => {
  const stixCoreObject = await storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  if (!stixCoreObject) {
    throw FunctionalError('Cannot delete the object, Stix-Core-Object cannot be found.');
  }
  await deleteElementById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  return stixCoreObjectId;
};

export const askElementEnrichmentForConnector = async (context, user, enrichedId, connectorId) => {
  const connector = await storeLoadById(context, user, connectorId, ENTITY_TYPE_CONNECTOR);
  const element = await internalLoadById(context, user, enrichedId);
  if (!element) {
    throw FunctionalError('Cannot enrich the object, element cannot be found.');
  }
  // If we are in a draft, specify it in work message and send draft_id in message
  const draftContext = getDraftContext(context, user);
  const contextOutOfDraft = { ...context, draft_context: '' };
  const workMessage = draftContext ? `Manual enrichment in draft ${draftContext}` : 'Manual enrichment';
  const work = await createWork(contextOutOfDraft, user, connector, workMessage, element.standard_id);
  const message = {
    internal: {
      work_id: work.id, // Related action for history
      applicant_id: null, // No specific user asking for the import
      draft_id: draftContext ?? null,
    },
    event: {
      event_type: CONNECTOR_INTERNAL_ENRICHMENT,
      entity_id: element.standard_id,
      entity_type: element.entity_type,
    },
  };
  await pushToConnector(connector.internal_id, message);
  const baseData = {
    id: enrichedId,
    connector_id: connectorId,
    connector_name: connector.name,
    entity_name: extractEntityRepresentativeName(element),
    entity_type: element.entity_type
  };
  const contextData = completeContextDataForEntity(baseData, element);
  await publishUserAction({
    user,
    event_access: 'extended',
    event_type: 'command',
    event_scope: 'enrich',
    context_data: contextData,
  });
  return work;
};

// region stats
export const stixCoreObjectsTimeSeries = (context, user, args) => {
  const types = extractStixCoreObjectTypesFromArgs(args);
  return timeSeriesEntities(context, user, types, args);
};

export const stixCoreObjectsTimeSeriesByAuthor = (context, user, args) => {
  const { authorId, types } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_CREATED_BY, '*'), authorId);
  return timeSeriesEntities(context, user, types ?? [ABSTRACT_STIX_CORE_OBJECT], { ...args, filters });
};

export const stixCoreObjectsMultiTimeSeries = (context, user, args) => {
  return Promise.all(args.timeSeriesParameters.map((timeSeriesParameter) => {
    const types = extractStixCoreObjectTypesFromArgs(timeSeriesParameter);
    return { data: timeSeriesEntities(context, user, types, { ...args, ...timeSeriesParameter }) };
  }));
};

export const stixCoreObjectsNumber = (context, user, args) => {
  const types = extractStixCoreObjectTypesFromArgs(args);
  return {
    count: elCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_ENTITIES : READ_ENTITIES_INDICES, { ...args, types }),
    total: elCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_ENTITIES : READ_ENTITIES_INDICES, { ...R.dissoc('endDate', args), types }),
  };
};

export const stixCoreObjectsMultiNumber = (context, user, args) => {
  return Promise.all(args.numberParameters.map((numberParameter) => {
    const types = extractStixCoreObjectTypesFromArgs(numberParameter);
    return {
      count: elCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_ENTITIES
        : READ_ENTITIES_INDICES, { ...args, ...numberParameter, types }),
      total: elCount(context, user, args.onlyInferred ? READ_INDEX_INFERRED_ENTITIES
        : READ_ENTITIES_INDICES, R.dissoc('endDate', { ...args, ...numberParameter, types }))
    };
  }));
};

export const stixCoreObjectsConnectedNumber = (stixCoreObject) => {
  return Object.entries(stixCoreObject)
    .filter(([key]) => key.startsWith(REL_INDEX_PREFIX))
    .map(([, value]) => value.length)
    .reduce((a, b) => a + b, 0);
};

export const stixCoreObjectsDistribution = async (context, user, args) => {
  const { types } = args;
  return distributionEntities(context, user, types ?? [ABSTRACT_STIX_CORE_OBJECT], args);
};

export const stixCoreObjectsDistributionByEntity = async (context, user, args) => {
  const { objectId, types, filters = {
    mode: 'and',
    filters: [],
    filterGroups: [],
  } } = args;
  let finalFilters = filters;
  // Here, we need to force regardingOf ID = objectID
  // Check if filter is already present and replace id
  if (findFiltersFromKey(filters.filters ?? [], INSTANCE_REGARDING_OF).length > 0) {
    finalFilters = {
      ...filters,
      filters: finalFilters.filters.map((n) => (n.key === INSTANCE_REGARDING_OF ? {
        ...n,
        values: [
          ...n.values.filter((i) => i.key !== 'id'),
          { key: 'id', values: [objectId] }
        ]
      } : n))
    };
  // If not present, adding it
  } else {
    finalFilters = addFilter(filters, INSTANCE_REGARDING_OF, [
      { key: 'id', values: [objectId] },
      { key: 'type', values: [ABSTRACT_STIX_CORE_RELATIONSHIP] }
    ]);
  }
  return distributionEntities(context, user, types ?? [ABSTRACT_STIX_CORE_OBJECT], { ...args, filters: finalFilters });
};

export const stixCoreObjectsMultiDistribution = (context, user, args) => {
  return Promise.all(args.distributionParameters.map((distributionParameter) => {
    const { types } = distributionParameter;
    return { data: distributionEntities(context, user, types ?? [ABSTRACT_STIX_CORE_OBJECT], { ...args, ...distributionParameter }) };
  }));
};
// endregion

// region export
export const stixCoreObjectsExportAsk = async (context, user, args) => {
  if (getDraftContext(context, user)) {
    throw UnsupportedError('Cannot ask for export in draft');
  }
  const { exportContext, format, exportType, contentMaxMarkings, selectedIds, fileMarkings } = args;
  const { search, orderBy, orderMode, filters } = args;
  const argsFilters = { search, orderBy, orderMode, filters };
  const ordersOpts = stixCoreObjectOptions.StixCoreObjectsOrdering;
  const listParams = exportTransformFilters(argsFilters, ordersOpts);
  const works = await askListExport(context, user, exportContext, format, selectedIds, listParams, exportType, contentMaxMarkings, fileMarkings);
  return works.map((w) => workToExportFile(w));
};
export const stixCoreObjectExportAsk = async (context, user, stixCoreObjectId, input) => {
  if (getDraftContext(context, user)) {
    throw UnsupportedError('Cannot ask for export in draft');
  }
  const { format, exportType, contentMaxMarkings, fileMarkings } = input;
  const entity = await storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  const works = await askEntityExport(context, user, format, entity, exportType, contentMaxMarkings, fileMarkings);
  return works.map((w) => workToExportFile(w));
};

export const stixCoreObjectsExportPush = async (context, user, entity_id, entity_type, file, file_markings, listFilters) => {
  const meta = { list_filters: listFilters };
  const entity = entity_id ? await internalLoadById(context, user, entity_id) : undefined;
  const opts = { entity, meta, file_markings };
  await uploadToStorage(context, user, `export/${entity_type}${entity_id ? `/${entity_id}` : ''}`, file, opts);
  return true;
};

export const stixCoreObjectExportPush = async (context, user, entityId, args) => {
  const previous = await storeLoadByIdWithRefs(context, user, entityId);
  if (!previous) {
    throw UnsupportedError('Cant upload a file an none existing element', { entityId });
  }
  const path = `export/${previous.entity_type}/${entityId}`;
  const { upload: up } = await uploadToStorage(context, user, path, args.file, { entity: previous, file_markings: args.file_markings });
  const contextData = buildContextDataForFile(previous, path, up.name);
  await publishUserAction({
    user,
    event_type: 'file',
    event_access: 'extended',
    event_scope: 'create',
    context_data: contextData
  });
  return true;
};

export const CONTENT_TYPE_FIELDS = 'fields';
export const CONTENT_TYPE_FILE = 'file';

export const askElementAnalysisForConnector = async (context, user, analyzedId, contentSource, contentType, connectorId) => {
  if (getDraftContext(context, user)) {
    throw UnsupportedError('Cannot ask for analysis in draft');
  }
  logApp.debug(`[JOBS] ask analysis for content type ${contentType} and content source ${contentSource}`);

  if (contentType === CONTENT_TYPE_FIELDS) return await askFieldsAnalysisForConnector(context, user, analyzedId, contentSource, connectorId);
  if (contentType === CONTENT_TYPE_FILE) return await askFileAnalysisForConnector(context, user, analyzedId, contentSource, connectorId);
  throw FunctionalError('Content type not recognized', { contentType });
};

export const CONTENT_SOURCE_CONTENT_MAPPING = 'content_mapping';

const askFieldsAnalysisForConnector = async (context, user, analyzedId, contentSource, connectorId) => {
  let connectors = await connectorsForAnalysis(context, user);
  if (connectorId) {
    connectors = R.filter((n) => n.id === connectorId, connectors);
  }
  if (connectors.length > 0) {
    // If a connectorId was specified, we use it, otherwise we get the first available connector by default. This way query can be called even without specifiying connectorId
    const connector = connectors[0];
    const element = await internalLoadById(context, user, analyzedId);
    const work = await createWork(context, user, connector, 'Content fields analysis', element.standard_id);

    if (contentSource !== CONTENT_SOURCE_CONTENT_MAPPING) {
      throw FunctionalError('Fields content source not handled', { contentSource });
    }

    const contentMappingFields = ['description', 'content'];
    const content_fields = contentMappingFields.join(' ');

    const message = {
      internal: {
        work_id: work.id, // Related action for history
        applicant_id: null, // No specific user asking for the analysis
      },
      event: {
        event_type: CONNECTOR_INTERNAL_ANALYSIS,
        entity_id: element.standard_id,
        entity_type: element.entity_type,
        content_type: CONTENT_TYPE_FIELDS,
        content_source: contentSource,
        content_fields,
        analysis_name: getAnalysisFileName(contentSource, CONTENT_TYPE_FIELDS),
      },
    };

    await pushToConnector(connector.internal_id, message);
    await publishAnalysisAction(user, analyzedId, connector, element);
    return work;
  }
  throw new ResourceNotFoundError('No connector found for analysis', { analyzedId, connectorId });
};

const askFileAnalysisForConnector = async (context, user, analyzedId, contentSource, connectorId) => {
  const file = await loadFile(context, user, contentSource);

  let connectors = await connectorsForAnalysis(context, user, file.metaData.mimetype);
  if (connectorId) {
    connectors = R.filter((n) => n.id === connectorId, connectors);
  }
  if (connectors.length > 0) {
    const connector = connectors[0];
    const element = await internalLoadById(context, user, analyzedId);
    const work = await createWork(context, user, connector, 'Content file analysis', element.standard_id);

    const message = {
      internal: {
        work_id: work.id, // Related action for history
        applicant_id: null, // No specific user asking for the analysis
      },
      event: {
        event_type: CONNECTOR_INTERNAL_ANALYSIS,
        entity_id: element.standard_id,
        entity_type: element.entity_type,
        content_type: CONTENT_TYPE_FILE,
        content_source: contentSource,
        file_id: file.id,
        file_mime: file.metaData.mimetype,
        file_fetch: `/storage/get/${file.id}`, // Path to get the file
        analysis_name: getAnalysisFileName(file.name, CONTENT_TYPE_FILE),
      },
    };

    await pushToConnector(connector.internal_id, message);
    await publishAnalysisAction(user, analyzedId, connector, element);
    return work;
  }
  throw new ResourceNotFoundError('No connector found for analysis', { analyzedId, connectorId });
};

const getAnalysisFileName = (contentSource, contentType) => {
  return `${contentType}_analysis_${contentSource}.analysis`;
};

const publishAnalysisAction = async (user, analyzedId, connector, element) => {
  const baseData = {
    id: analyzedId,
    connector_id: connector.id,
    connector_name: connector.name,
    entity_name: extractEntityRepresentativeName(element),
    entity_type: element.entity_type
  };
  const contextData = completeContextDataForEntity(baseData, element);
  await publishUserAction({
    user,
    event_access: 'extended',
    event_type: 'command',
    event_scope: 'analyze',
    context_data: contextData,
  });
};

export const stixCoreObjectAnalysisPush = async (context, user, entityId, args) => {
  const entity = await internalLoadById(context, user, entityId);
  if (!entity) {
    throw UnsupportedError('Cant upload a file an none existing element', { entityId });
  }
  const { file, contentSource, contentType, analysisType } = args;
  const meta = { analysis_content_source: contentSource, analysis_content_type: contentType, analysis_type: analysisType };
  const path = `analysis/${entity.entity_type}/${entity.id}`;
  const { upload: up } = await uploadToStorage(context, user, path, file, { entity, meta });
  const contextData = buildContextDataForFile(entity, path, up.name);
  await publishUserAction({
    user,
    event_type: 'file',
    event_access: 'extended',
    event_scope: 'create',
    context_data: contextData
  });
  return up;
};

export const analysisClear = async (context, user, entityId, contentSource, contentType) => {
  const entity = await internalLoadById(context, user, entityId);
  if (!entity) {
    throw UnsupportedError('Cant clear analysis on none existing element', { entityId });
  }
  const analysisFilePath = `analysis/${entity.entity_type}/${entity.id}`;
  const analysisFilesPagination = await paginatedForPathWithEnrichment(context, context.user, analysisFilePath, entityId);
  const analysisFilesNodes = analysisFilesPagination.edges.map(({ node }) => node);
  for (let i = 0; i < analysisFilesNodes.length; i += 1) {
    const analysisFile = analysisFilesNodes[i];
    if (analysisFile?.metaData?.analysis_content_source === contentSource && analysisFile?.metaData?.analysis_content_type === contentType) {
      const upDelete = await deleteFile(context, context.user, analysisFile?.id);
      const contextData = buildContextDataForFile(entity, analysisFile?.id, upDelete.name);
      await publishUserAction({
        user,
        event_type: 'file',
        event_access: 'extended',
        event_scope: 'delete',
        context_data: contextData
      });
    }
  }

  return true;
};

export const stixCoreAnalysis = async (context, user, entityId, contentSource, contentType) => {
  const entity = await internalLoadById(context, user, entityId);
  if (!entity) {
    throw UnsupportedError('Cant get analysis on none existing element', { entityId });
  }

  // Get ongoing work if any. If work is ongoing, we don't need to look for analysis
  // TODO:  need to add content_source and content_type to work attributes to be able to correct filter works
  const works = await worksForSource(context, user, entity.standard_id, { type: CONNECTOR_INTERNAL_ANALYSIS });
  const filterCompletedWorks = works.filter((w) => w.status !== 'complete' && w.errors.length === 0);
  if (filterCompletedWorks.length > 0) {
    return { analysisType: 'mapping_analysis', analysisStatus: filterCompletedWorks[0].status };
  }

  // Retrieve analysis file for given contentSource and contentType
  const analysisFilePath = `analysis/${entity.entity_type}/${entity.id}`;
  const analysisFilesPagination = await paginatedForPathWithEnrichment(context, context.user, analysisFilePath, entityId);
  const analysisFilesNodes = analysisFilesPagination.edges.map(({ node }) => node);
  const analysis = analysisFilesNodes.find((a) => a.metaData?.analysis_content_source === contentSource && a.metaData?.analysis_content_type === contentType);
  if (!analysis) return null;

  // Get analysis file content as json data
  const analysisType = analysis.metaData.analysis_type;
  if (analysisType !== 'mapping_analysis') throw UnsupportedError('Analysis type not supported', { analysisType }); // We currently only handle one analysis type
  const analysisContent = await getFileContent(analysis.id);
  if (!analysisContent) throw UnsupportedError('Couldnt retrieve file', { analysis });
  const analysisParsedContent = JSON.parse(analysisContent);

  // Parse json data and transform it into MappedAnalysis object
  const entitiesToResolve = Object.values(analysisParsedContent).filter((i) => isNotEmptyField(i));
  const entitiesResolved = await elFindByIds(context, user, entitiesToResolve, { toMap: true, mapWithAllIds: true });
  const analysisDataConverted = (analysisKey) => {
    const analysisId = analysisParsedContent[analysisKey];
    const entityResolved = entitiesResolved[analysisId];
    const entityContainers = entityResolved?.[buildRefRelationKey(RELATION_OBJECT)];
    const isEntityInContainer = entityContainers ? entityContainers.some((c) => c === entity.id) : false;
    return { matchedString: analysisKey, matchedEntity: entityResolved, isEntityInContainer };
  };

  const mappedEntities = Object.keys(analysisParsedContent)
    .map((d) => analysisDataConverted(d))
    .filter((e) => e.matchedEntity);

  return { analysisType, mappedEntities, analysisStatus: 'complete', analysisDate: analysis.lastModified };
};

export const stixCoreObjectImportPush = async (context, user, id, file, args = {}) => {
  if (getDraftContext(context, user)) {
    throw UnsupportedError('Cannot import in draft');
  }
  let lock;
  const { noTriggerImport, version: fileVersion, fileMarkings: file_markings, importContextEntities, fromTemplate = false } = args;
  const previous = await storeLoadByIdWithRefs(context, user, id);
  if (!previous) {
    throw UnsupportedError('Cant upload a file an none existing element', { id });
  }
  // check entity access
  if (!validateUserAccessOperation(user, previous, 'edit')) {
    throw ForbiddenAccess();
  }
  const participantIds = getInstanceIds(previous);
  try {
    // Lock the participants that will be merged
    lock = await lockResources(participantIds);
    const { internal_id: internalId } = previous;
    const { filename } = await file;
    const entitySetting = await getEntitySettingFromCache(context, previous.entity_type);
    const isAutoExternal = !entitySetting ? false : entitySetting.platform_entity_files_ref;
    const filePath = fromTemplate
      ? `fromTemplate/${previous.entity_type}/${internalId}`
      : `import/${previous.entity_type}/${internalId}`;
    // 01. Upload the file
    const meta = { version: fileVersion?.toISOString() };
    if (isAutoExternal) {
      const key = `${filePath}/${filename}`;
      meta.external_reference_id = generateStandardId(ENTITY_TYPE_EXTERNAL_REFERENCE, { url: `/storage/get/${key}` });
    }
    const { upload: up, untouched } = await uploadToStorage(context, user, filePath, file, { meta, noTriggerImport, entity: previous, file_markings, importContextEntities });
    if (untouched) {
      // When synchronizing the version can be the same.
      // If it's the case, just return without any x_opencti_files modifications
      return up;
    }
    // 02. Create and link external ref if needed.
    let addedExternalRef;
    if (isAutoExternal) {
      // Create external ref + link to current entity
      const createExternal = { source_name: filename, url: `/storage/get/${up.id}`, fileId: up.id };
      const externalRef = await createEntity(context, user, createExternal, ENTITY_TYPE_EXTERNAL_REFERENCE);
      const relInput = { fromId: id, toId: externalRef.id, relationship_type: RELATION_EXTERNAL_REFERENCE };
      const opts = { publishStreamEvent: false, locks: participantIds };
      await createRelationRaw(context, user, relInput, opts);
      addedExternalRef = externalRef;
    }
    // Patch the updated_at to force live stream evolution
    const eventFile = storeFileConverter(user, up);
    const files = [...(previous.x_opencti_files ?? []).filter((f) => f.id !== up.id), eventFile];
    const nonResolvedFiles = files.map((f) => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { [INPUT_MARKINGS]: markingInput, ...nonResolvedFile } = f;
      return nonResolvedFile;
    });
    await elUpdateElement(context, user, {
      _index: previous._index,
      internal_id: internalId,
      entity_type: previous.entity_type, // required for schema validation
      updated_at: now(),
      x_opencti_files: nonResolvedFiles
    });
    // Stream event generation
    const fileMarkings = R.uniq(R.flatten(files.filter((f) => f.file_markings).map((f) => f.file_markings)));
    let fileMarkingsPromise = Promise.resolve();
    if (fileMarkings.length > 0) {
      const argsMarkings = { type: ENTITY_TYPE_MARKING_DEFINITION, toMap: true, connectionFormat: false, baseData: true };
      fileMarkingsPromise = elFindByIds(context, SYSTEM_USER, R.uniq(fileMarkings), argsMarkings);
    }
    const fileMarkingsMap = await fileMarkingsPromise;
    const resolvedFiles = [];
    files.forEach((f) => {
      if (isNotEmptyField(f.file_markings)) {
        resolvedFiles.push({ ...f, [INPUT_MARKINGS]: f.file_markings.map((m) => fileMarkingsMap[m]).filter((fm) => fm) });
      } else {
        resolvedFiles.push(f);
      }
    });
    if (addedExternalRef) {
      const newExternalRefs = [...(previous[INPUT_EXTERNAL_REFS] ?? []), addedExternalRef];
      const instance = { ...previous, x_opencti_files: resolvedFiles, [INPUT_EXTERNAL_REFS]: newExternalRefs };
      const message = `adds \`${up.name}\` in \`files\` and \`external_references\``;
      await storeUpdateEvent(context, user, previous, instance, message);
    } else {
      const instance = { ...previous, x_opencti_files: resolvedFiles };
      await storeUpdateEvent(context, user, previous, instance, `adds \`${up.name}\` in \`files\``);
    }
    // Add in activity only for notifications
    const contextData = buildContextDataForFile(previous, filePath, up.name, up.metaData.file_markings);
    await publishUserAction({
      user,
      event_type: 'file',
      event_access: 'extended',
      event_scope: 'create',
      prevent_indexing: true,
      context_data: contextData
    });
    return up;
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};

export const stixCoreObjectImportDelete = async (context, user, fileId) => {
  if (getDraftContext(context, user)) {
    throw UnsupportedError('Cannot delete imports in draft');
  }
  if (!fileId.startsWith('import')) {
    throw UnsupportedError('Cant delete an exported file with this method');
  }
  // Get the context
  const baseDocument = await documentFindById(context, user, fileId);
  if (!baseDocument) {
    throw UnsupportedError('File removed or inaccessible', { fileId });
  }
  const entityId = baseDocument.metaData.entity_id;
  const externalReferenceId = baseDocument.metaData.external_reference_id;
  const previous = await storeLoadByIdWithRefs(context, user, entityId);
  if (!previous) {
    throw UnsupportedError('Cant delete a file of none existing element', { entityId });
  }
  // check entity access
  if (!validateUserAccessOperation(user, previous, 'edit')) {
    throw ForbiddenAccess();
  }
  let lock;
  const participantIds = getInstanceIds(previous);
  try {
    // Lock the participants that will be merged
    lock = await lockResources(participantIds);
    // If external reference attached, delete first
    if (externalReferenceId) {
      try {
        await deleteElementById(context, user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
      } catch {
        // If external reference already deleted.
      }
    }
    // Delete the file
    await deleteFile(context, user, fileId);
    // Patch the updated_at to force live stream evolution
    const files = (previous.x_opencti_files ?? []).filter((f) => f.id !== fileId);
    const nonResolvedFiles = files.map((f) => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { [INPUT_MARKINGS]: markingInput, ...nonResolvedFile } = f;
      return nonResolvedFile;
    });
    await elUpdateElement(context, user, {
      _index: previous._index,
      internal_id: entityId,
      updated_at: now(),
      x_opencti_files: nonResolvedFiles,
      entity_type: previous.entity_type, // required for schema validation
    });
    // Stream event generation
    const instance = { ...previous, x_opencti_files: files };
    await storeUpdateEvent(context, user, previous, instance, `removes \`${baseDocument.name}\` in \`files\``);
    // Add in activity only for notifications
    const contextData = buildContextDataForFile(previous, fileId, baseDocument.name);
    await publishUserAction({
      user,
      event_type: 'file',
      event_access: 'extended',
      event_scope: 'delete',
      prevent_indexing: true,
      context_data: contextData
    });
    await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, instance, user);
  } catch (err) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
};

// region context
export const stixCoreObjectCleanContext = async (context, user, stixCoreObjectId) => {
  await delEditContext(user, stixCoreObjectId);
  return storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT).then((stixCoreObject) => {
    return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, stixCoreObject, user);
  });
};

export const stixCoreObjectEditContext = async (context, user, stixCoreObjectId, input) => {
  await setEditContext(user, stixCoreObjectId, input);
  return storeLoadById(context, user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT).then((stixCoreObject) => {
    return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, stixCoreObject, user);
  });
};
// endregion

// region ai
export const aiActivity = async (context, user, args) => {
  await checkEnterpriseEdition(context);

  const { id, language = 'English', forceRefresh = false } = args;
  // Resolve in cache
  const identifier = `${id}-activity`;
  if (!forceRefresh && aiResponseCache[identifier] && utcDate(aiResponseCache[identifier].updatedAt).isAfter(minutesAgo(AI_INSIGHTS_REFRESH_TIMEOUT))) {
    await notify(BUS_TOPICS[AI_BUS].EDIT_TOPIC, { bus_id: identifier, content: aiResponseCache[identifier].result }, user);
    return aiResponseCache[identifier];
  }
  // Resolve the entity
  const stixCoreObject = await storeLoadById(context, user, id, ABSTRACT_STIX_CORE_OBJECT);
  // Activity
  let result = '';
  if (threats.includes(stixCoreObject.entity_type)) {
    result = await aiActivityForThreats(context, user, stixCoreObject, language);
  }
  if (victims.includes(stixCoreObject.entity_type)) {
    result = await aiActivityForVictims(context, user, stixCoreObject, language);
  }
  let trend = '';
  if (threats.includes(stixCoreObject.entity_type)) {
    trend = await aiActivityTrendForThreats(context, user, stixCoreObject);
  }
  if (victims.includes(stixCoreObject.entity_type)) {
    trend = await aiActivityTrendForVictims(context, user, stixCoreObject);
  }

  // refine result
  const finalResult = result
    .replace('```html', '')
    .replace('```', '')
    .replace('<html>', '')
    .replace('</html>', '')
    .replace('<body>', '')
    .replace('</body>', '')
    .trim();

  const activity = {
    result: finalResult,
    trend,
    updated_at: now()
  };
  aiResponseCache[identifier] = activity;
  return activity;
};

export const aiForecast = async (context, user, args) => {
  await checkEnterpriseEdition(context);

  const { id, language = 'English', forceRefresh = false } = args;
  // Resolve in cache
  const identifier = `${id}-forecast`;
  if (!forceRefresh && aiResponseCache[identifier] && utcDate(aiResponseCache[identifier].updatedAt).isAfter(minutesAgo(AI_INSIGHTS_REFRESH_TIMEOUT))) {
    return aiResponseCache[identifier];
  }
  // Resolve the entity
  const stixCoreObject = await storeLoadById(context, user, id, ABSTRACT_STIX_CORE_OBJECT);
  // Activity
  let result = '';
  if (threats.includes(stixCoreObject.entity_type)) {
    result = await aiForecastForThreats(context, user, stixCoreObject, language);
  }
  if (victims.includes(stixCoreObject.entity_type)) {
    result = await aiForecastForVictims(context, user, stixCoreObject, language);
  }

  // refine result
  const finalResult = result
    .replace('```html', '')
    .replace('```', '')
    .replace('<html>', '')
    .replace('</html>', '')
    .replace('<body>', '')
    .replace('</body>', '')
    .trim();

  const activity = {
    result: finalResult,
    updated_at: now()
  };
  aiResponseCache[identifier] = activity;
  return activity;
};

export const aiHistory = async (context, user, args) => {
  await checkEnterpriseEdition(context);
  const { id, language = 'English', forceRefresh = false } = args;
  // Resolve in cache
  const identifier = `${id}-history`;
  if (!forceRefresh && aiResponseCache[identifier] && utcDate(aiResponseCache[identifier].updatedAt).isAfter(minutesAgo(AI_INSIGHTS_REFRESH_TIMEOUT))) {
    return aiResponseCache[identifier];
  }
  // Resolve the entity
  const stixCoreObject = await storeLoadById(context, user, id, ABSTRACT_STIX_CORE_OBJECT);
  // Resolve logs
  const logs = await getHistory(context, user, stixCoreObject.id);
  const userPrompt = `
  # Instructions

  - You have to compute a summary of the given logs representing the history of creation and modifications of a ${stixCoreObject.entity_type} in the OpenCTI platform.
  - The summary should be about the latest activities performed by a user, which can be an analyst (human) or a connector (data source or enrichment) on the ${stixCoreObject.entity_type}.
  - Create a comprehensive summary in HTML format.
  - Don't give too much details, really summarize and highlight the history of modifications of the entity.
  - The summary should be formatted in HTML.
  - The summary should be in ${language} language.
  - In the HTML format, don't use h1 (first level title), start with h2.    
    
  # Context
  
  - The summary is about the ${stixCoreObject.entity_type} ${stixCoreObject.name} (${(stixCoreObject.aliases ?? []).join(', ')}). 
  - The description of the ${stixCoreObject.entity_type} ${stixCoreObject.name} is ${stixCoreObject.description}.
  
  # Data
  
  ## Logs
  This is the latest 200 logs entries of this entity.
  ${JSON.stringify(logs)}
  `;
  // Get results
  const result = await queryAi(identifier, systemPrompt, userPrompt, user);

  // refine result
  const finalResult = result
    .replace('```html', '')
    .replace('```', '')
    .replace('<html>', '')
    .replace('</html>', '')
    .replace('<body>', '')
    .replace('</body>', '')
    .trim();

  const history = { result: finalResult, updated_at: now() };
  aiResponseCache[identifier] = history;
  return history;
};

// region prompts for threats
export const aiActivityForThreats = async (context, user, stixCoreObject, language) => {
  const indicatorsStats = await getIndicatorsStats(context, user, stixCoreObject.id, monthsAgo(24), now());
  const victimologyStats = await getVictimologyStats(context, user, stixCoreObject.id, monthsAgo(24), now());
  const topSectors = {};
  // eslint-disable-next-line no-plusplus
  for (let i = 0; i < 8; i++) {
    topSectors[`From ${monthsAgo(i * 3 + 3)} to ${monthsAgo(i * 3)}`] = await getTopVictims(context, user, stixCoreObject.id, [ENTITY_TYPE_IDENTITY_SECTOR], monthsAgo(i * 3 + 3), monthsAgo(i * 3));
  }
  const topCountries = {};
  // eslint-disable-next-line no-plusplus
  for (let i = 0; i < 8; i++) {
    topCountries[`From ${monthsAgo(i * 3 + 3)} to ${monthsAgo(i * 3)}`] = await getTopVictims(context, user, stixCoreObject.id, [ENTITY_TYPE_LOCATION_COUNTRY], monthsAgo(i * 3 + 3), monthsAgo(i * 3));
  }
  const topRegions = {};
  // eslint-disable-next-line no-plusplus
  for (let i = 0; i < 8; i++) {
    topRegions[`From ${monthsAgo(i * 3 + 3)} to ${monthsAgo(i * 3)}`] = await getTopVictims(context, user, stixCoreObject.id, [ENTITY_TYPE_LOCATION_REGION], monthsAgo(i * 3 + 3), monthsAgo(i * 3));
  }

  const userPrompt = `
  # Context
  - You are a cyber threat intelligence analyst. 
  - Your task is to create a comprehensive summary based on statistics and trends about a threat.
  
  # Instructions

  - You have to compute a summary of approximately 500 words based on the following statistics / trends about a ${stixCoreObject.entity_type}.
  - The summary should be about the latest activities of the ${stixCoreObject.entity_type} and highlight the variations of numbers over time.
  - The summary should not repeat numbers, but aggregate them in a meaningful way to stay short and comprehensive.
  - The summary should be in ${language} language.
  - The summary should be formatted in HTML and highlight important numbers with bold. 
  - Your response should be only the summary and nothing else.
  - Your response should not contain any generic assumptions or recommendations, it should rely only on the given context and statistics.
  - In the HTML format, don't use h1 (first level title), start with h2.
  
  # Interpretation of the data
  - Increasing of indicators of compromise is indicating a surge in the ${stixCoreObject.entity_type} activity, which is BAD.
  - Decreasing of indicators of compromise is indicating a reduction in the ${stixCoreObject.entity_type} activity, which is GOOD.
  - Increasing of victims is indicating a surge in the ${stixCoreObject.entity_type} activity, which is BAD.
  - Decreasing of victims of compromise is indicating a reduction in the ${stixCoreObject.entity_type} activity, which is GOOD.
  
  # Context
  
  - The summary is about the ${stixCoreObject.entity_type} ${stixCoreObject.name} (${(stixCoreObject.aliases ?? []).join(', ')}). 
  - The description of the${stixCoreObject.entity_type} ${stixCoreObject.name} is ${stixCoreObject.description}.
  
  # Data
  
  ## Last indicators of compromise (IOCs) statistics.
  This is the number of indicators related to this ${stixCoreObject.entity_type} over time:
  ${JSON.stringify(indicatorsStats)}
  
  ## Last victims statistics
  This is the number of times this ${stixCoreObject.entity_type} has targeted something, whether it is an organization, a sector, a location, etc.:
  ${JSON.stringify(victimologyStats)}
  
  ## Top targeted sectors over time
  This is the top sectors targeted over time:
  ${JSON.stringify(topSectors)}
  
  ## Top targeted countries over time
  This is the top countries targeted over time:
  ${JSON.stringify(topCountries)}
  
  ## Top targeted regions over time
  This is the top regions targeted over time:
  ${JSON.stringify(topRegions)}
  `;

  return queryAi(`${stixCoreObject.id}-activity`, systemPrompt, userPrompt, user);
};

export const aiActivityTrendForThreats = async (context, user, stixCoreObject) => {
  const indicatorsStats = await getIndicatorsStats(context, user, stixCoreObject.id, monthsAgo(24), now());
  const victimologyStats = await getVictimologyStats(context, user, stixCoreObject.id, monthsAgo(24), now());

  const userPrompt = `
  # Context
  - You are a cyber threat intelligence analyst. 
  - Your task is to categorize a trend about a cyber threat in 4 categories:
    - increasing: The threat activity is showing a significant increase.
    - stable: The threat activity is stable with minor fluctuations whether down or up.
    - decreasing: The threat activity is showing a significant decrease.
    - unknown: The evaluation of the threat activity cannot be done (not enough data, etc.).
     
  # Instructions

  - Based on the following data, you have to categorize the recent activity of a ${stixCoreObject.entity_type}. 
  - Categories are:
    - increasing: The threat activity is showing a significant increase.
    - stable: The threat activity is stable with minor fluctuations whether down or up.
    - decreasing: The threat activity is showing a significant decrease.
    - unknown: The evaluation of the threat activity cannot be done (not enough data, etc.).
  - Your response answer should be only one word with the category keyword and nothing else.
  - Your response should not contain any generic assumptions or recommendations, it should rely only on the given context and statistics.
  
  # Interpretation of the data
  - Increasing of indicators of compromise is indicating a surge in the ${stixCoreObject.entity_type} activity.
  - Decreasing of indicators of compromise is indicating a reduction in the ${stixCoreObject.entity_type} activity.
  - Increasing of victims is indicating a surge in the ${stixCoreObject.entity_type} activity.
  - Decreasing of victims of compromise is indicating a reduction in the ${stixCoreObject.entity_type} activity.
    
  # Data
  
  ## Last indicators of compromise (IOCs) statistics.
  This is the number of indicators related to this ${stixCoreObject.entity_type} over time:
  ${JSON.stringify(indicatorsStats)}
  
  ## Last victims statistics
  This is the number of times this ${stixCoreObject.entity_type} has targeted something, whether it is an organization, a sector, a location, etc.:
  ${JSON.stringify(victimologyStats)}
  `;

  return queryAi(`${stixCoreObject.id}-activity`, systemPrompt, userPrompt, user);
};

export const aiForecastForThreats = async (context, user, stixCoreObject, language) => {
  const indicatorsStats = await getIndicatorsStats(context, user, stixCoreObject.id, monthsAgo(24), now());
  const victimologyStats = await getVictimologyStats(context, user, stixCoreObject.id, monthsAgo(24), now());
  const topSectors = {};
  // eslint-disable-next-line no-plusplus
  for (let i = 0; i < 8; i++) {
    topSectors[`From ${monthsAgo(i * 3 + 3)} to ${monthsAgo(i * 3)}`] = await getTopVictims(context, user, stixCoreObject.id, [ENTITY_TYPE_IDENTITY_SECTOR], monthsAgo(i * 3 + 3), monthsAgo(i * 3));
  }
  const topCountries = {};
  // eslint-disable-next-line no-plusplus
  for (let i = 0; i < 8; i++) {
    topCountries[`From ${monthsAgo(i * 3 + 3)} to ${monthsAgo(i * 3)}`] = await getTopVictims(context, user, stixCoreObject.id, [ENTITY_TYPE_LOCATION_COUNTRY], monthsAgo(i * 3 + 3), monthsAgo(i * 3));
  }
  const topRegions = {};
  // eslint-disable-next-line no-plusplus
  for (let i = 0; i < 8; i++) {
    topRegions[`From ${monthsAgo(i * 3 + 3)} to ${monthsAgo(i * 3)}`] = await getTopVictims(context, user, stixCoreObject.id, [ENTITY_TYPE_LOCATION_REGION], monthsAgo(i * 3 + 3), monthsAgo(i * 3));
  }

  const userPrompt = `
  # Context
  - You are a cyber threat intelligence analyst. 
  - Your task is to create a forecast report based on statistics and trends about a threat.
  
  # Instructions

  - You have to compute a forecast report of approximately 500 words based on the following statistics / trends about a ${stixCoreObject.entity_type}.
  - The summary should be about the potential upcoming activities of the ${stixCoreObject.entity_type}.
  - The summary should be in ${language} language.
  - The summary should be formatted in HTML and highlight important numbers with bold.
  - Your response should be only the forecast report and nothing else.
  - Your response should not contain any generic assumptions or recommendations, it should rely only on the given context and statistics.
  - In the HTML format, don't use h1 (first level title), start with h2.
  
  # Interpretation of the data
  - Increasing of indicators of compromise is indicating a surge in the ${stixCoreObject.entity_type} activity, which is BAD.
  - Decreasing of indicators of compromise is indicating a reduction in the ${stixCoreObject.entity_type} activity, which is GOOD.
  - Increasing of victims is indicating a surge in the ${stixCoreObject.entity_type} activity, which is BAD.
  - Decreasing of victims of compromise is indicating a reduction in the ${stixCoreObject.entity_type} activity, which is GOOD.
  
  # Context
  
  - The forecast is about the ${stixCoreObject.entity_type} ${stixCoreObject.name} (${(stixCoreObject.aliases ?? []).join(', ')}). 
  - The description of the${stixCoreObject.entity_type} ${stixCoreObject.name} is ${stixCoreObject.description}.
  
  # Data
  
  ## Last indicators of compromise (IOCs) statistics.
  This is the number of indicators related to this ${stixCoreObject.entity_type} over time:
  ${JSON.stringify(indicatorsStats)}
  
  ## Last victims statistics
  This is the number of times this ${stixCoreObject.entity_type} has targeted something, whether it is an organization, a sector, a location, etc.:
  ${JSON.stringify(victimologyStats)}
  
  ## Top targeted sectors over time
  This is the top sectors targeted over time:
  ${JSON.stringify(topSectors)}
  
  ## Top targeted countries over time
  This is the top countries targeted over time:
  ${JSON.stringify(topCountries)}
  
  ## Top targeted regions over time
  This is the top regions targeted over time:
  ${JSON.stringify(topRegions)}
  `;

  return queryAi(`${stixCoreObject.id}-forecast`, systemPrompt, userPrompt, user);
};
// endregion

// region prompts for victims
export const aiActivityForVictims = async (context, user, stixCoreObject, language) => {
  const targetingStats = await getTargetingStats(context, user, stixCoreObject.id, monthsAgo(24), now());
  const containersStats = await getContainersStats(context, user, stixCoreObject.id, monthsAgo(24), now());
  const topIntrusionSets = {};
  // eslint-disable-next-line no-plusplus
  for (let i = 0; i < 8; i++) {
    topIntrusionSets[`From ${monthsAgo(i * 3 + 3)} to ${monthsAgo(i * 3)}`] = await getTopThreats(context, user, stixCoreObject.id, [ENTITY_TYPE_INTRUSION_SET], monthsAgo(i * 3 + 3), monthsAgo(i * 3));
  }
  const topMalwares = {};
  // eslint-disable-next-line no-plusplus
  for (let i = 0; i < 8; i++) {
    topMalwares[`From ${monthsAgo(i * 3 + 3)} to ${monthsAgo(i * 3)}`] = await getTopThreats(context, user, stixCoreObject.id, [ENTITY_TYPE_MALWARE], monthsAgo(i * 3 + 3), monthsAgo(i * 3));
  }

  const userPrompt = `
  # Context
  - You are a cyber threat intelligence analyst. 
  - Your task is to create a comprehensive summary based on statistics and trends about a targeted entity.
  
  # Instructions

  - You have to compute a summary of approximately 500 words based on the following statistics / trends about a ${stixCoreObject.entity_type}.
  - The summary should be about the latest activities of the ${stixCoreObject.entity_type} and highlight the variations of numbers over time.
  - The summary should not repeat numbers, but aggregate them in a meaningful way to stay short and comprehensive.
  - The summary should be in ${language} language.
  - The summary should be formatted in HTML and highlight important numbers with bold. 
  - Your response should be only the summary and nothing else.
  - Your response should not contain any generic assumptions or recommendations, it should rely only on the given context and statistics.
  - In the HTML format, don't use h1 (first level title), start with h2.
  
  # Interpretation of the data
  - Increasing of containers is indicating a surge in the ${stixCoreObject.entity_type} activity, which is BAD.
  - Decreasing of containers is indicating a reduction in the ${stixCoreObject.entity_type} activity, which is GOOD.
  - Increasing of targets is indicating a surge in the ${stixCoreObject.entity_type} being targeted, which is BAD.
  - Decreasing of targets of compromise is indicating a reduction in the ${stixCoreObject.entity_type} being targeted, which is GOOD.
  
  # Context
  
  - The summary is about the ${stixCoreObject.entity_type} ${stixCoreObject.name} (${(stixCoreObject.aliases ?? []).join(', ')}). 
  - The description of the${stixCoreObject.entity_type} ${stixCoreObject.name} is ${stixCoreObject.description}.
  
  # Data
  
  ## Last containers stats (reports, incidents etc.)
  This is the number of containers related to this ${stixCoreObject.entity_type} over time:
  ${JSON.stringify(containersStats)}
  
  ## Last targets stats
  This is the number of times this ${stixCoreObject.entity_type} has been targeted by something, whether it is an intrusion set, malware, etc.
  ${JSON.stringify(targetingStats)}
  
  ## Top intrusion sets over time
  This is the top intrusion sets targeting this ${stixCoreObject.entity_type} over time:
  ${JSON.stringify(topIntrusionSets)}
  
  ## Top malwares over time
  This is the top malwares targeting this ${stixCoreObject.entity_type} over time:
  ${JSON.stringify(topMalwares)}
  `;

  return queryAi(`${stixCoreObject.id}-activity`, systemPrompt, userPrompt, user);
};

export const aiActivityTrendForVictims = async (context, user, stixCoreObject) => {
  const targetingStats = await getTargetingStats(context, user, stixCoreObject.id, monthsAgo(24), now());
  const containersStats = await getContainersStats(context, user, stixCoreObject.id, monthsAgo(24), now());

  const userPrompt = `
  # Context
  - You are a cyber threat intelligence analyst. 
  - Your task is to categorize a trend about a cyber threat in 4 categories:
    - increasing: The threat activity is showing a significant increase.
    - stable: The threat activity is stable with minor fluctuations whether down or up.
    - decreasing: The threat activity is showing a significant decrease.
    - unknown: The evaluation of the threat activity cannot be done (not enough data, etc.).
     
  # Instructions

  - Based on the following data, you have to categorize the recent activity of a ${stixCoreObject.entity_type}. 
  - Categories are:
    - increasing: The threat activity is showing a significant increase.
    - stable: The threat activity is stable with minor fluctuations whether down or up.
    - decreasing: The threat activity is showing a significant decrease.
    - unknown: The evaluation of the threat activity cannot be done (not enough data, etc.).
  - Your response answer should be only one word with the category keyword and nothing else.
  - Your response should not contain any generic assumptions or recommendations, it should rely only on the given context and statistics.
  
# Interpretation of the data
  - Increasing of containers is indicating a surge in the ${stixCoreObject.entity_type} activity, which is BAD.
  - Decreasing of containers is indicating a reduction in the ${stixCoreObject.entity_type} activity, which is GOOD.
  - Increasing of targets is indicating a surge in the ${stixCoreObject.entity_type} being targeted, which is BAD.
  - Decreasing of targets of compromise is indicating a reduction in the ${stixCoreObject.entity_type} being targeted, which is GOOD.
    
  # Data
  
  ## Last containers stats (reports, incidents etc.)
  This is the number of containers related to this ${stixCoreObject.entity_type} over time:
  ${JSON.stringify(containersStats)}
  
  ## Last targets stats
  This is the number of times this ${stixCoreObject.entity_type} has been targeted by something, whether it is an intrusion set, malware, etc.
  ${JSON.stringify(targetingStats)}
  `;

  return queryAi(`${stixCoreObject.id}-activity`, systemPrompt, userPrompt, user);
};

export const aiForecastForVictims = async (context, user, stixCoreObject, language) => {
  const targetingStats = await getTargetingStats(context, user, stixCoreObject.id, monthsAgo(24), now());
  const containersStats = await getContainersStats(context, user, stixCoreObject.id, monthsAgo(24), now());
  const topIntrusionSets = {};
  // eslint-disable-next-line no-plusplus
  for (let i = 0; i < 8; i++) {
    topIntrusionSets[`From ${monthsAgo(i * 3 + 3)} to ${monthsAgo(i * 3)}`] = await getTopThreats(context, user, stixCoreObject.id, [ENTITY_TYPE_INTRUSION_SET], monthsAgo(i * 3 + 3), monthsAgo(i * 3));
  }
  const topMalwares = {};
  // eslint-disable-next-line no-plusplus
  for (let i = 0; i < 8; i++) {
    topMalwares[`From ${monthsAgo(i * 3 + 3)} to ${monthsAgo(i * 3)}`] = await getTopThreats(context, user, stixCoreObject.id, [ENTITY_TYPE_MALWARE], monthsAgo(i * 3 + 3), monthsAgo(i * 3));
  }

  const userPrompt = `
  # Context
  - You are a cyber threat intelligence analyst. 
  - Your task is to create a forecast report based on statistics and trends about a targeted entity.
  
  # Instructions

  - You have to compute a forecast report of approximately 500 words based on the following statistics / trends about a ${stixCoreObject.entity_type}.
  - The summary should be about the potential upcoming activities and targeting of the ${stixCoreObject.entity_type}.
  - The summary should be in ${language} language.
  - The summary should be formatted in HTML and highlight important numbers with bold.
  - Your response should be only the forecast report and nothing else.
  - Your response should not contain any generic assumptions or recommendations, it should rely only on the given context and statistics.
  - In the HTML format, don't use h1 (first level title), start with h2.
  
# Interpretation of the data
  - Increasing of containers is indicating a surge in the ${stixCoreObject.entity_type} activity, which is BAD.
  - Decreasing of containers is indicating a reduction in the ${stixCoreObject.entity_type} activity, which is GOOD.
  - Increasing of targets is indicating a surge in the ${stixCoreObject.entity_type} being targeted, which is BAD.
  - Decreasing of targets of compromise is indicating a reduction in the ${stixCoreObject.entity_type} being targeted, which is GOOD.
  
  # Context
  
  - The forecast is about the ${stixCoreObject.entity_type} ${stixCoreObject.name} (${(stixCoreObject.aliases ?? []).join(', ')}). 
  - The description of the${stixCoreObject.entity_type} ${stixCoreObject.name} is ${stixCoreObject.description}.
  
  # Data
  
  ## Last containers stats (reports, incidents etc.)
  This is the number of containers related to this ${stixCoreObject.entity_type} over time:
  ${JSON.stringify(containersStats)}
  
  ## Last targets stats
  This is the number of times this ${stixCoreObject.entity_type} has been targeted by something, whether it is an intrusion set, malware, etc.
  ${JSON.stringify(targetingStats)}
  
  ## Top intrusion sets over time
  This is the top intrusion sets targeting this ${stixCoreObject.entity_type} over time:
  ${JSON.stringify(topIntrusionSets)}
  
  ## Top malwares over time
  This is the top malwares targeting this ${stixCoreObject.entity_type} over time:
  ${JSON.stringify(topMalwares)}
  `;

  return queryAi(`${stixCoreObject.id}-forecast`, systemPrompt, userPrompt, user);
};
// endregion
