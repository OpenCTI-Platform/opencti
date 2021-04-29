import * as R from 'ramda';
import { createHash } from 'crypto';
import { assoc, dissoc, map, pipe, filter } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  createRelations,
  deleteElementById,
  deleteRelationsByFromAndTo,
  distributionEntities,
  listEntities,
  loadById,
  timeSeriesEntities,
  updateAttribute,
  batchListThroughGetFrom,
  listThroughGetFrom,
  fullLoadById,
} from '../database/middleware';
import { BUS_TOPICS, logApp } from '../config/conf';
import { elCount } from '../database/elasticSearch';
import { READ_INDEX_STIX_CYBER_OBSERVABLES } from '../database/utils';
import { createWork, workToExportFile } from './work';
import { pushToConnector } from '../database/rabbitmq';
import { addIndicator } from './indicator';
import { askEnrich } from './enrichment';
import { FunctionalError } from '../config/errors';
import { createStixPattern } from '../python/pythonBridge';
import { checkObservableSyntax } from '../utils/syntax';
import { upload } from '../database/minio';
import {
  ENTITY_AUTONOMOUS_SYSTEM,
  ENTITY_DIRECTORY,
  ENTITY_EMAIL_MESSAGE,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE,
  ENTITY_MUTEX,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PROCESS,
  ENTITY_SOFTWARE,
  ENTITY_USER_ACCOUNT,
  ENTITY_WINDOWS_REGISTRY_KEY,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE,
  isStixCyberObservable,
  isStixCyberObservableHashedObservable,
  stixCyberObservableOptions,
} from '../schema/stixCyberObservable';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_META_RELATIONSHIP } from '../schema/general';
import { isStixMetaRelationship, RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { RELATION_BASED_ON } from '../schema/stixCoreRelationship';
import { ENTITY_TYPE_INDICATOR } from '../schema/stixDomainObject';
import { apiAttributeToComplexFormat } from '../schema/fieldDataAdapter';
import { askEntityExport, askListExport, exportTransformFilters } from './stixCoreObject';
import { escape } from '../utils/format';
import { uploadJobImport } from './file';

export const findById = (user, stixCyberObservableId) => {
  return loadById(user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
};

export const findAll = async (user, args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = filter((type) => isStixCyberObservable(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CYBER_OBSERVABLE);
  }
  return listEntities(user, types, args);
};

// region by elastic
export const stixCyberObservablesNumber = (user, args) => ({
  count: elCount(user, READ_INDEX_STIX_CYBER_OBSERVABLES, args),
  total: elCount(user, READ_INDEX_STIX_CYBER_OBSERVABLES, dissoc('endDate', args)),
});
// endregion

// region time series
export const reportsTimeSeries = (user, stixCyberObservableId, args) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: stixCyberObservableId }];
  return timeSeriesEntities(user, 'Report', filters, args);
};

export const stixCyberObservablesTimeSeries = (user, args) => {
  return timeSeriesEntities(user, args.type ? escape(args.type) : ABSTRACT_STIX_CYBER_OBSERVABLE, [], args);
};
// endregion

// region mutations
export const stixCyberObservableAskEnrichment = async (user, observableId, connectorId) => {
  const connector = await loadById(user, connectorId, ENTITY_TYPE_CONNECTOR);
  const work = await createWork(user, connector, 'Manual enrichment', observableId);
  const message = {
    internal: {
      work_id: work.id, // Related action for history
      applicant_id: user.id, // User asking for the import
    },
    event: {
      entity_id: observableId,
    },
  };
  await pushToConnector(connector, message);
  return work;
};

export const batchIndicators = (user, stixCyberObservableIds) => {
  return batchListThroughGetFrom(user, stixCyberObservableIds, RELATION_BASED_ON, ENTITY_TYPE_INDICATOR);
};

export const hashValue = (stixCyberObservable) => {
  if (stixCyberObservable.hashes) {
    for (const algo of ['SHA-256', 'SHA-1', 'MD5']) {
      if (stixCyberObservable.hashes[algo]) {
        return stixCyberObservable.hashes[algo];
      }
    }
  }
  return null;
};

export const observableValue = (stixCyberObservable) => {
  switch (stixCyberObservable.entity_type) {
    case ENTITY_AUTONOMOUS_SYSTEM:
      return stixCyberObservable.name || stixCyberObservable.number || 'Unknown';
    case ENTITY_DIRECTORY:
      return stixCyberObservable.path || 'Unknown';
    case ENTITY_EMAIL_MESSAGE:
      return stixCyberObservable.body || stixCyberObservable.subject;
    case ENTITY_HASHED_OBSERVABLE_ARTIFACT:
      return hashValue(stixCyberObservable) || stixCyberObservable.payload_bin || 'Unknown';
    case ENTITY_HASHED_OBSERVABLE_STIX_FILE:
      return hashValue(stixCyberObservable) || stixCyberObservable.name || 'Unknown';
    case ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE:
      return hashValue(stixCyberObservable) || stixCyberObservable.subject || stixCyberObservable.issuer || 'Unknown';
    case ENTITY_MUTEX:
      return stixCyberObservable.name || 'Unknown';
    case ENTITY_NETWORK_TRAFFIC:
      return stixCyberObservable.dst_port || 'Unknown';
    case ENTITY_PROCESS:
      return stixCyberObservable.pid || stixCyberObservable.command_line || 'Unknown';
    case ENTITY_SOFTWARE:
      return stixCyberObservable.name || 'Unknown';
    case ENTITY_USER_ACCOUNT:
      return stixCyberObservable.account_login || stixCyberObservable.user_id || 'Unknown';
    case ENTITY_WINDOWS_REGISTRY_KEY:
      return stixCyberObservable.attribute_key || 'Unknown';
    case ENTITY_WINDOWS_REGISTRY_VALUE_TYPE:
      return stixCyberObservable.name || stixCyberObservable.data || 'Unknown';
    default:
      return stixCyberObservable.value || 'Unknown';
  }
};

const createIndicatorFromObservable = async (user, input, observable) => {
  try {
    let entityType = observable.entity_type;
    let key = entityType;
    if (isStixCyberObservableHashedObservable(entityType)) {
      if (observable.hashes) {
        if (observable.hashes['SHA-256']) {
          key = `${entityType}_sha256`;
        } else if (observable.hashes['SHA-1']) {
          key = `${entityType}_sha1`;
        } else if (observable.hashes.MD5) {
          key = `${entityType}_md5`;
        }
      } else if (observable.name) {
        key = `${entityType}_name`;
      }
    }
    if (observable.pid) {
      key = `${entityType}_pid`;
    }
    const indicatorName = observableValue(observable);
    if (key.includes('StixFile')) {
      key = key.replace('StixFile', 'File');
    }
    if (key.includes('Artifact')) {
      key = key.replace('Artifact', 'File');
      entityType = 'StixFile';
    }
    const pattern = await createStixPattern(key, indicatorName);
    if (pattern) {
      const indicatorToCreate = {
        pattern_type: 'stix',
        pattern,
        x_opencti_main_observable_type: entityType,
        name: indicatorName,
        description: observable.x_opencti_description
          ? observable.x_opencti_description
          : `Simple indicator of observable {${indicatorName}}`,
        basedOn: [observable.id],
        x_opencti_score: observable.x_opencti_score,
        createdBy: input.createdBy,
        objectMarking: input.objectMarking,
        objectLabel: input.objectLabel,
        externalReferences: input.externalReferences,
        update: true,
      };
      await addIndicator(user, indicatorToCreate);
    }
  } catch (err) {
    logApp.info(`[OPENCTI] Cannot create indicator`, { error: err });
  }
};

export const promoteObservableToIndicator = async (user, observableId) => {
  const observable = await fullLoadById(user, observableId);
  const objectLabel =
    observable.i_relations_from && observable.i_relations_from['object-label']
      ? observable.i_relations_from['object-label'].map((n) => n.internal_id)
      : [];
  const objectMarking =
    observable.i_relations_from && observable.i_relations_from['object-marking']
      ? observable.i_relations_from['object-marking'].map((n) => n.internal_id)
      : [];
  const createdBy =
    observable.i_relations_from &&
    observable.i_relations_from['created-by'] &&
    observable.i_relations_from['created-by'].length > 0
      ? observable.i_relations_from['created-by'].map((n) => n.internal_id)[0]
      : [];
  await createIndicatorFromObservable(user, { objectLabel, objectMarking, createdBy }, observable);
  return observable;
};

export const addStixCyberObservable = async (user, input) => {
  // The input type must be a correct observable type
  if (!isStixCyberObservable(input.type)) {
    throw FunctionalError(`Observable type ${input.type} is not supported.`);
  }
  // If type is ok, get the correct data that represent the observable
  const graphQLType = input.type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase());
  let observableInput = pipe(
    dissoc('type'),
    dissoc('createIndicator')
  )({ ...dissoc(graphQLType, input), ...input[graphQLType] });
  if (!observableInput) {
    throw FunctionalError(`Expecting variable ${graphQLType} in the input, got nothing.`);
  }
  // Convert hashes to dictionary if needed.
  if (isStixCyberObservableHashedObservable(input.type) && observableInput.hashes) {
    const hashInputToJson = apiAttributeToComplexFormat('hashes', observableInput.hashes);
    observableInput = R.assoc('hashes', hashInputToJson, observableInput);
  }
  // Check the consistency of the observable.
  const observableSyntaxResult = checkObservableSyntax(input.type, observableInput);
  if (observableSyntaxResult !== true) {
    throw FunctionalError(`Observable of type ${input.type} is not correctly formatted.`, { observableSyntaxResult });
  }
  // If everything ok, create adapt/create the observable and notify for enrichment
  const created = await createEntity(user, observableInput, input.type);
  if (!created.i_upserted) {
    await askEnrich(user, created.id, input.type);
  }
  // create the linked indicator if needed
  if (input.createIndicator) {
    await createIndicatorFromObservable(user, input, created);
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].ADDED_TOPIC, created, user);
};

export const stixCyberObservableDelete = async (user, stixCyberObservableId) => {
  return deleteElementById(user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
};

export const stixCyberObservableAddRelation = async (user, stixCyberObservableId, input) => {
  const stixCyberObservable = await loadById(user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
  if (!stixCyberObservable) {
    throw FunctionalError('Cannot add the relation, Stix-Cyber-Observable cannot be found.');
  }
  if (!isStixMetaRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = assoc('fromId', stixCyberObservableId, input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].EDIT_TOPIC, relationData, user);
    return relationData;
  });
};

export const stixCyberObservableAddRelations = async (user, stixCyberObservableId, input) => {
  const stixCyberObservable = await loadById(user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
  if (!stixCyberObservable) {
    throw FunctionalError('Cannot add the relation, Stix-Cyber-Observable cannot be found.');
  }
  if (!isStixMetaRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = map(
    (n) => ({ fromId: stixCyberObservableId, toId: n, relationship_type: input.relationship_type }),
    input.toIds
  );
  await createRelations(user, finalInput);
  return loadById(user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE).then((entity) =>
    notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].EDIT_TOPIC, entity, user)
  );
};

export const stixCyberObservableDeleteRelation = async (user, stixCyberObservableId, toId, relationshipType) => {
  const stixCyberObservable = await loadById(user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
  if (!stixCyberObservable) {
    throw FunctionalError('Cannot delete the relation, Stix-Cyber-Observable cannot be found.');
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(
    user,
    stixCyberObservableId,
    toId,
    relationshipType,
    ABSTRACT_STIX_META_RELATIONSHIP
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].EDIT_TOPIC, stixCyberObservable, user);
};

export const stixCyberObservableEditField = async (user, stixCyberObservableId, input, options = {}) => {
  const stixCyberObservable = await updateAttribute(
    user,
    stixCyberObservableId,
    ABSTRACT_STIX_CYBER_OBSERVABLE,
    input,
    options
  );
  if (input.key === 'x_opencti_score') {
    const indicators = await listThroughGetFrom(
      user,
      [stixCyberObservableId],
      RELATION_BASED_ON,
      ENTITY_TYPE_INDICATOR
    );
    await Promise.all(
      indicators.map((indicator) => updateAttribute(user, indicator.id, ENTITY_TYPE_INDICATOR, input, options))
    );
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].EDIT_TOPIC, stixCyberObservable, user);
};
// endregion

// region context
export const stixCyberObservableCleanContext = (user, stixCyberObservableId) => {
  delEditContext(user, stixCyberObservableId);
  return loadById(user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE).then((stixCyberObservable) =>
    notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].EDIT_TOPIC, stixCyberObservable, user)
  );
};
export const stixCyberObservableEditContext = (user, stixCyberObservableId, input) => {
  setEditContext(user, stixCyberObservableId, input);
  return loadById(user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE).then((stixCyberObservable) =>
    notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].EDIT_TOPIC, stixCyberObservable, user)
  );
};
// endregion

// region export
export const stixCyberObservablesExportAsk = async (user, args) => {
  const { format, exportType, maxMarkingDefinition } = args;
  const { search, orderBy, orderMode, filters, filterMode, types } = args;
  const argsFilters = { search, orderBy, orderMode, filters, filterMode, types };
  const filtersOpts = stixCyberObservableOptions.StixCyberObservablesFilter;
  const ordersOpts = stixCyberObservableOptions.StixCyberObservablesOrdering;
  const listParams = exportTransformFilters(argsFilters, filtersOpts, ordersOpts);
  const works = await askListExport(
    user,
    format,
    'Stix-Cyber-Observable',
    listParams,
    exportType,
    maxMarkingDefinition
  );
  return map((w) => workToExportFile(w), works);
};
export const stixCyberObservableExportAsk = async (user, args) => {
  const { format, exportType, stixCyberObservableId = null, maxMarkingDefinition = null } = args;
  const entity = stixCyberObservableId
    ? await loadById(user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE)
    : null;
  const works = await askEntityExport(user, format, entity, exportType, maxMarkingDefinition);
  return map((w) => workToExportFile(w.work), works);
};
export const stixCyberObservablesExportPush = async (user, file, listFilters) => {
  await upload(user, `export/Stix-Cyber-Observable`, file, { list_filters: listFilters });
  return true;
};
export const stixCyberObservableExportPush = async (user, entityId, file) => {
  await upload(user, `export/Stix-Cyber-Observable/${entityId}`, file, { entity_id: entityId });
  return true;
};
// endregion

// region mutation
export const stixCyberObservableDistribution = async (user, args) =>
  distributionEntities(user, ABSTRACT_STIX_CYBER_OBSERVABLE, [], args);

export const stixCyberObservableDistributionByEntity = async (user, args) => {
  const { objectId } = args;
  const filters = [{ isRelation: true, type: args.relationship_type, value: objectId }];
  return distributionEntities(user, ABSTRACT_STIX_CYBER_OBSERVABLE, filters, args);
};

const checksumFile = async (hashName, stream) => {
  return new Promise((resolve, reject) => {
    const hash = createHash(hashName);
    stream.on('error', (err) => reject(err));
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
};

export const artifactImport = async (user, args) => {
  const { file, x_opencti_description: description, createdBy, objectMarking, objectLabel } = args;
  const { createReadStream, filename, mimetype } = await file;
  const artifactData = {
    type: 'Artifact',
    Artifact: {
      x_opencti_description: description || 'Artifact uploaded',
      x_opencti_additional_names: [filename],
      mime_type: mimetype,
      hashes: [
        { algorithm: 'MD5', hash: await checksumFile('md5', createReadStream()) },
        { algorithm: 'SHA-1', hash: await checksumFile('sha1', createReadStream()) },
        { algorithm: 'SHA-256', hash: await checksumFile('sha256', createReadStream()) },
      ],
    },
    createdBy,
    objectMarking,
    objectLabel,
  };
  const artifact = await addStixCyberObservable(user, artifactData);
  const up = await upload(user, `import/${artifact.entity_type}/${artifact.id}`, file, { entity_id: artifact.id });
  await uploadJobImport(user, up.id, up.metaData.mimetype, up.metaData.entity_id);
  return artifact;
};
