import { assoc, dissoc, filter, map } from 'ramda';
import { createHash } from 'node:crypto';
import { v4 as uuidv4 } from 'uuid';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  batchListThroughGetFrom,
  batchListThroughGetTo,
  batchLoadThroughGetTo,
  createEntity,
  createRelation,
  createRelations,
  deleteElementById,
  deleteRelationsByFromAndTo,
  distributionEntities,
  listThroughGetFrom,
  storeLoadByIdWithRefs,
  timeSeriesEntities,
  updateAttribute
} from '../database/middleware';
import { internalLoadById, listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS, logApp } from '../config/conf';
import { elCount } from '../database/engine';
import { isNotEmptyField, READ_INDEX_STIX_CYBER_OBSERVABLES } from '../database/utils';
import { workToExportFile } from './work';
import { addIndicator } from './indicator';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { createStixPattern } from '../python/pythonBridge';
import { checkObservableSyntax } from '../utils/syntax';
import { upload } from '../database/file-storage';
import {
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  isStixCyberObservable,
  isStixCyberObservableHashedObservable,
  stixCyberObservableOptions
} from '../schema/stixCyberObservable';
import {
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_META_RELATIONSHIP, buildRefRelationKey,
  INPUT_CREATED_BY,
  INPUT_LABELS,
  INPUT_MARKINGS
} from '../schema/general';
import { isStixMetaRelationship } from '../schema/stixMetaRelationship';
import { RELATION_BASED_ON, RELATION_HAS, RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import {
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_VULNERABILITY
} from '../schema/stixDomainObject';
import { inputHashesToStix } from '../schema/fieldDataAdapter';
import { askEntityExport, askListExport, exportTransformFilters } from './stix';
import { now, observableValue } from '../utils/format';
import { RELATION_CONTENT, RELATION_SERVICE_DLL } from '../schema/stixCyberObservableRelationship';

export const findById = (context, user, stixCyberObservableId) => {
  return storeLoadById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
};

export const findAll = async (context, user, args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = filter((type) => isStixCyberObservable(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CYBER_OBSERVABLE);
  }
  return listEntities(context, user, types, args);
};

// region by elastic
export const stixCyberObservablesNumber = (context, user, args) => ({
  count: elCount(context, user, READ_INDEX_STIX_CYBER_OBSERVABLES, args),
  total: elCount(context, user, READ_INDEX_STIX_CYBER_OBSERVABLES, dissoc('endDate', args)),
});
// endregion

// region time series
export const stixCyberObservablesTimeSeries = (context, user, args) => {
  const { types = [ABSTRACT_STIX_CYBER_OBSERVABLE] } = args;
  return timeSeriesEntities(context, user, types, args);
};
// endregion

// region mutations

const createIndicatorFromObservable = async (context, user, input, observable) => {
  try {
    let entityType = observable.entity_type;
    let key = entityType;
    const indicatorName = observableValue(observable);
    let value = indicatorName;
    if (isStixCyberObservableHashedObservable(entityType)) {
      if (observable.hashes) {
        key = '';
        value = '';
        if (observable.hashes['SHA-256']) {
          key = `${entityType}_sha256`;
          value = observable.hashes['SHA-256'];
        }
        if (observable.hashes['SHA-1']) {
          key = key.length > 0 ? `${key}__${entityType}_sha1` : `${entityType}_sha1`;
          value = value.length > 0 ? `${value}__${observable.hashes['SHA-1']}` : observable.hashes['SHA-1'];
        }
        if (observable.hashes.MD5) {
          key = key.length > 0 ? `${key}__${entityType}_md5` : `${entityType}_md5`;
          value = value.length > 0 ? `${value}__${observable.hashes.MD5}` : observable.hashes.MD5;
        }
      } else if (observable.name) {
        key = `${entityType}_name`;
      }
    } else if (observable.pid) {
      key = `${entityType}_pid`;
    } else if (observable.subject) {
      key = `${entityType}_subject`;
    } else if (observable.body) {
      key = `${entityType}_body`;
    }
    if (key.includes('StixFile')) {
      key = key.replaceAll('StixFile', 'File');
    }
    if (key.includes('Artifact')) {
      key = key.replaceAll('Artifact', 'File');
      entityType = 'StixFile';
    }
    const pattern = await createStixPattern(context, user, key, value);
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
      await addIndicator(context, user, indicatorToCreate);
    } else {
      logApp.warn(`[OPENCTI] Cannot create indicator for ${key} / ${value} - cant generate pattern`);
    }
  } catch (err) {
    logApp.info('[OPENCTI] Cannot create indicator', { error: err });
  }
};

export const promoteObservableToIndicator = async (context, user, observableId) => {
  const observable = await storeLoadByIdWithRefs(context, user, observableId);
  const objectLabel = (observable[INPUT_LABELS] ?? []).map((n) => n.internal_id);
  const objectMarking = (observable[INPUT_MARKINGS] ?? []).map((n) => n.internal_id);
  const createdBy = observable[INPUT_CREATED_BY]?.internal_id;
  await createIndicatorFromObservable(context, user, { objectLabel, objectMarking, createdBy }, observable);
  return observable;
};

export const addStixCyberObservable = async (context, user, input) => {
  // The input type must be a correct observable type
  if (!isStixCyberObservable(input.type)) {
    throw FunctionalError(`Observable type ${input.type} is not supported.`);
  }
  // If type is ok, get the correct data that represent the observable
  const {
    stix_id,
    x_opencti_score,
    x_opencti_description,
    createdBy,
    objectMarking,
    objectLabel,
    externalReferences,
    update,
    type,
    createIndicator,
    payload_bin,
    url,
  } = input;
  const graphQLType = type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase());
  if (!input[graphQLType]) {
    throw FunctionalError(`Expecting variable ${graphQLType} in the input, got nothing.`);
  }

  const observableInput = {
    stix_id,
    x_opencti_score,
    x_opencti_description,
    createdBy,
    objectMarking,
    objectLabel,
    externalReferences,
    update,
    ...input[graphQLType]
  };
  if (isNotEmptyField(payload_bin) && isNotEmptyField(url)) {
    throw FunctionalError('Cannot create observable with both payload_bin and url filled.');
  }
  // Convert hashes to dictionary if needed.
  if (isStixCyberObservableHashedObservable(type) && observableInput.hashes) {
    observableInput.hashes = inputHashesToStix(observableInput.hashes);
  }
  // Check the consistency of the observable.
  const observableSyntaxResult = checkObservableSyntax(type, observableInput);
  if (observableSyntaxResult !== true) {
    throw FunctionalError(`Observable of type ${type} is not correctly formatted.`, { observableSyntaxResult });
  }
  // If everything ok, create adapt/create the observable
  const created = await createEntity(context, user, observableInput, type);
  // create the linked indicator if needed
  if (createIndicator) {
    await createIndicatorFromObservable(context, user, input, created);
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].ADDED_TOPIC, created, user);
};

export const stixCyberObservableDelete = async (context, user, stixCyberObservableId) => {
  return deleteElementById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
};

export const stixCyberObservableAddRelation = async (context, user, stixCyberObservableId, input) => {
  const stixCyberObservable = await storeLoadById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
  if (!stixCyberObservable) {
    throw FunctionalError('Cannot add the relation, Stix-Cyber-Observable cannot be found.');
  }
  const finalInput = assoc('fromId', stixCyberObservableId, input);
  return createRelation(context, user, finalInput).then((relationData) => {
    notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].EDIT_TOPIC, relationData, user);
    return relationData;
  });
};

export const stixCyberObservableAddRelations = async (context, user, stixCyberObservableId, input) => {
  const stixCyberObservable = await storeLoadById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
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
  await createRelations(context, user, finalInput);
  return storeLoadById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE)
    .then((entity) => notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].EDIT_TOPIC, entity, user));
};

export const stixCyberObservableDeleteRelation = async (context, user, stixCyberObservableId, toId, relationshipType) => {
  const stixCyberObservable = await storeLoadById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
  if (!stixCyberObservable) {
    throw FunctionalError('Cannot delete the relation, Stix-Cyber-Observable cannot be found.');
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(
    context,
    user,
    stixCyberObservableId,
    toId,
    relationshipType,
    ABSTRACT_STIX_META_RELATIONSHIP
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].EDIT_TOPIC, stixCyberObservable, user);
};

export const stixCyberObservableEditField = async (context, user, stixCyberObservableId, input, opts = {}) => {
  const originalStixCyberObservable = await storeLoadById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
  if (isNotEmptyField(originalStixCyberObservable.payload_bin) && input[0].key === 'url') {
    if (isNotEmptyField(originalStixCyberObservable.url)) {
      await updateAttribute(
        context,
        user,
        stixCyberObservableId,
        ABSTRACT_STIX_CYBER_OBSERVABLE,
        [{ key: 'url', values: null }],
        opts
      );
    }
    throw FunctionalError('Cannot update url when payload_bin is present.');
  } else if (isNotEmptyField(originalStixCyberObservable.url) && input[0].key === 'payload_bin') {
    if (isNotEmptyField(originalStixCyberObservable.payload_bin)) {
      await updateAttribute(
        context,
        user,
        stixCyberObservableId,
        ABSTRACT_STIX_CYBER_OBSERVABLE,
        [{ key: 'payload_bin', values: null }],
        opts
      );
    }
    throw FunctionalError('Cannot update payload_bin when url is present.');
  }
  const { element: stixCyberObservable } = await updateAttribute(
    context,
    user,
    stixCyberObservableId,
    ABSTRACT_STIX_CYBER_OBSERVABLE,
    input,
    opts
  );
  if (input[0].key === 'x_opencti_score') {
    const indicators = await listThroughGetFrom(
      context,
      user,
      [stixCyberObservableId],
      RELATION_BASED_ON,
      ENTITY_TYPE_INDICATOR
    );
    await Promise.all(
      indicators.map((indicator) => updateAttribute(context, user, indicator.id, ENTITY_TYPE_INDICATOR, input, opts))
    );
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].EDIT_TOPIC, stixCyberObservable, user);
};
// endregion

// region context
export const stixCyberObservableCleanContext = (context, user, stixCyberObservableId) => {
  delEditContext(user, stixCyberObservableId);
  return storeLoadById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE).then((stixCyberObservable) => {
    return notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].EDIT_TOPIC, stixCyberObservable, user);
  });
};
export const stixCyberObservableEditContext = (context, user, stixCyberObservableId, input) => {
  setEditContext(user, stixCyberObservableId, input);
  return storeLoadById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE).then((stixCyberObservable) => {
    return notify(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].EDIT_TOPIC, stixCyberObservable, user);
  });
};
// endregion

// region export
export const stixCyberObservablesExportAsk = async (context, user, args) => {
  const { format, exportType, maxMarkingDefinition } = args;
  const { search, orderBy, orderMode, filters, filterMode, types } = args;
  const argsFilters = { search, orderBy, orderMode, filters, filterMode, types };
  const filtersOpts = stixCyberObservableOptions.StixCyberObservablesFilter;
  const ordersOpts = stixCyberObservableOptions.StixCyberObservablesOrdering;
  const listParams = exportTransformFilters(argsFilters, filtersOpts, ordersOpts);
  const works = await askListExport(
    context,
    user,
    format,
    'Stix-Cyber-Observable',
    listParams,
    exportType,
    maxMarkingDefinition
  );
  return works.map((w) => workToExportFile(w));
};
export const stixCyberObservableExportAsk = async (context, user, args) => {
  const { format, exportType, stixCyberObservableId = null, maxMarkingDefinition = null } = args;
  const entity = stixCyberObservableId
    ? await storeLoadById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE)
    : null;
  const works = await askEntityExport(context, user, format, entity, exportType, maxMarkingDefinition);
  return map((w) => workToExportFile(w.work), works);
};
export const stixCyberObservablesExportPush = async (context, user, file, listFilters) => {
  await upload(context, user, 'export/Stix-Cyber-Observable', file, { list_filters: listFilters });
  return true;
};
export const stixCyberObservableExportPush = async (context, user, entityId, file) => {
  const entity = await internalLoadById(context, user, entityId);
  if (!entity) {
    throw UnsupportedError('Cant upload a file an none existing element', { entityId });
  }
  await upload(context, user, `export/Stix-Cyber-Observable/${entityId}`, file, { entity_id: entityId });
  return true;
};
// endregion

// region mutation
export const stixCyberObservableDistribution = async (context, user, args) => {
  const { types = [ABSTRACT_STIX_CYBER_OBSERVABLE] } = args;
  return distributionEntities(context, user, types, args);
};

export const stixCyberObservableDistributionByEntity = async (context, user, args) => {
  const { relationship_type, objectId, types = [ABSTRACT_STIX_CYBER_OBSERVABLE] } = args;
  const filters = [{ key: [relationship_type.map((n) => buildRefRelationKey(n, '*'))], values: [objectId] }, ...(args.filters || [])];
  return distributionEntities(context, user, types, { ...args, filters });
};

const checksumFile = async (hashName, stream) => {
  return new Promise((resolve, reject) => {
    const hash = createHash(hashName);
    stream.on('error', (err) => reject(err));
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
};

export const artifactImport = async (context, user, args) => {
  const { file, x_opencti_description: description, createdBy, objectMarking, objectLabel } = args;
  const { createReadStream, filename, mimetype } = await file;
  const targetId = uuidv4();
  const filePath = `import/${ENTITY_HASHED_OBSERVABLE_ARTIFACT}/${targetId}`;
  const version = now();
  const artifactData = {
    internal_id: targetId,
    type: ENTITY_HASHED_OBSERVABLE_ARTIFACT,
    Artifact: {
      x_opencti_description: description || 'Artifact uploaded',
      x_opencti_additional_names: [filename],
      x_opencti_files: [{
        id: `${filePath}/${filename}`,
        name: filename,
        version,
        mime_type: mimetype,
      }],
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
  const artifact = await addStixCyberObservable(context, user, artifactData);
  await upload(context, user, `import/${artifact.entity_type}/${artifact.id}`, file, { entity_id: artifact.id, version });
  return artifact;
};

export const batchIndicators = (context, user, stixCyberObservableIds) => {
  return batchListThroughGetFrom(context, user, stixCyberObservableIds, RELATION_BASED_ON, ENTITY_TYPE_INDICATOR);
};

export const batchVulnerabilities = (context, user, softwareIds) => {
  return batchListThroughGetTo(context, user, softwareIds, RELATION_HAS, ENTITY_TYPE_VULNERABILITY);
};

export const batchStixFiles = (user, softwareIds) => {
  return batchListThroughGetTo(user, softwareIds, RELATION_SERVICE_DLL, ENTITY_HASHED_OBSERVABLE_STIX_FILE);
};

export const batchArtifacts = (context, user, softwareIds) => {
  return batchLoadThroughGetTo(context, user, softwareIds, RELATION_CONTENT, ENTITY_HASHED_OBSERVABLE_ARTIFACT);
};

export const batchCountries = (context, user, ipIds) => {
  return batchListThroughGetTo(context, user, ipIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_COUNTRY);
};
