import { createHash } from 'node:crypto';
import { Readable } from 'stream';
import nconf from 'nconf';
import { dissoc } from 'ramda';
import unzipper from 'unzipper';
import { streamToBuffer } from '@jorgeferrero/stream-to-buffer';
import { fileTypeFromBuffer } from 'file-type';
import { v4 as uuidv4 } from 'uuid';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { createEntity, deleteElementById, distributionEntities, storeLoadByIdWithRefs, timeSeriesEntities, updateAttribute } from '../database/middleware';
import {
  doesUserHaveAccess,
  listAllFromEntitiesThroughRelations,
  listEntities,
  listEntitiesThroughRelationsPaginated,
  loadEntityThroughRelationsPaginated,
  storeLoadById
} from '../database/middleware-loader';
import { BUS_TOPICS, logApp } from '../config/conf';
import { elCount } from '../database/engine';
import { isEmptyField, isNotEmptyField, READ_INDEX_STIX_CYBER_OBSERVABLES } from '../database/utils';
import { workToExportFile } from './work';
import { addIndicator } from '../modules/indicator/indicator-domain';
import { ForbiddenAccess, FunctionalError } from '../config/errors';
import { createStixPattern } from '../python/pythonBridge';
import { checkObservableSyntax, STIX_PATTERN_TYPE } from '../utils/syntax';
import { upload } from '../database/file-storage';
import {
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  isStixCyberObservable,
  isStixCyberObservableHashedObservable,
  stixCyberObservableOptions
} from '../schema/stixCyberObservable';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, buildRefRelationKey, INPUT_CREATED_BY, INPUT_GRANTED_REFS, INPUT_LABELS, INPUT_MARKINGS } from '../schema/general';
import { RELATION_CONTENT, RELATION_SERVICE_DLL } from '../schema/stixRefRelationship';
import { RELATION_BASED_ON, RELATION_HAS } from '../schema/stixCoreRelationship';
import { ENTITY_TYPE_VULNERABILITY } from '../schema/stixDomainObject';
import { inputHashesToStix } from '../schema/fieldDataAdapter';
import { askEntityExport, askListExport, exportTransformFilters } from './stix';
import { now, observableValue } from '../utils/format';
import { stixObjectOrRelationshipAddRefRelation, stixObjectOrRelationshipDeleteRefRelation } from './stixObjectOrStixRelationship';
import { addFilter } from '../utils/filtering/filtering-utils';
import { ENTITY_TYPE_INDICATOR } from '../modules/indicator/indicator-types';

export const findById = (context, user, stixCyberObservableId) => {
  const stixCyberObservable = storeLoadById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
  // Check permissions
  if (!doesUserHaveAccess(user, 'KNOWLEDGE', stixCyberObservable.entity_type)) {
    throw ForbiddenAccess();
  }
  return stixCyberObservable;
};

export const findAll = async (context, user, args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = args.types.filter((type) => isStixCyberObservable(type)
      && doesUserHaveAccess(user, 'KNOWLEDGE', type), args.types);
  }
  if (types.length === 0) {
    if (!doesUserHaveAccess(user, 'KNOWLEDGE', ABSTRACT_STIX_CYBER_OBSERVABLE)) {
      throw ForbiddenAccess();
    }
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
export const generateKeyValueForIndicator = (entityType, indicatorName, observable) => {
  let key = entityType;
  let value = indicatorName;
  if (isStixCyberObservableHashedObservable(entityType)) {
    if (observable.hashes) {
      key = '';
      value = '';
      if (observable.hashes['SHA-256']) {
        key = `${entityType}_sha256`;
        value = observable.hashes['SHA-256'];
      }
      if (observable.hashes['SHA-512']) {
        key = `${entityType}_sha512`;
        value = observable.hashes['SHA-512'];
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
    value = observable.subject;
  } else if (observable.body) {
    key = `${entityType}_body`;
    value = observable.body;
  }
  if (key.includes('StixFile')) {
    key = key.replaceAll('StixFile', 'File');
  }
  if (key.includes('Artifact')) {
    key = key.replaceAll('Artifact', 'File');
  }
  return { key, value };
};
const createIndicatorFromObservable = async (context, user, input, observable) => {
  try {
    let entityType = observable.entity_type;
    const indicatorName = observableValue(observable);
    const { key, value } = generateKeyValueForIndicator(entityType, indicatorName, observable);
    if (key.includes('Artifact')) {
      entityType = 'StixFile';
    }
    const pattern = await createStixPattern(context, user, key, value);
    if (pattern) {
      const indicatorToCreate = {
        pattern_type: STIX_PATTERN_TYPE,
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
        objectOrganization: input.objectOrganization,
        objectLabel: input.objectLabel,
        externalReferences: input.externalReferences,
        update: true,
      };
      await addIndicator(context, user, indicatorToCreate);
    } else {
      logApp.warn('Cannot create indicator - cant generate pattern', { key, value });
    }
  } catch (err) {
    logApp.info('[OPENCTI] Cannot create indicator', { error: err });
  }
};

export const promoteObservableToIndicator = async (context, user, observableId) => {
  const observable = await storeLoadByIdWithRefs(context, user, observableId);
  const objectLabel = (observable[INPUT_LABELS] ?? []).map((n) => n.internal_id);
  const objectMarking = (observable[INPUT_MARKINGS] ?? []).map((n) => n.internal_id);
  const objectOrganization = (observable[INPUT_GRANTED_REFS] ?? []).map((n) => n.internal_id);
  const createdBy = observable[INPUT_CREATED_BY]?.internal_id;
  await createIndicatorFromObservable(context, user, { objectLabel, objectMarking, objectOrganization, createdBy }, observable);
  return observable;
};

export const addStixCyberObservable = async (context, user, input) => {
  // The input type must be a correct observable type
  if (!isStixCyberObservable(input.type)) {
    throw FunctionalError(`Observable type ${input.type} is not supported.`);
  }
  // Check permissions
  if (!doesUserHaveAccess(user, 'KNOWLEDGE_KNUPDATE', input.type)) {
    throw ForbiddenAccess();
  }
  // If type is ok, get the correct data that represent the observable
  const {
    stix_id,
    x_opencti_score,
    x_opencti_description,
    createdBy,
    objectMarking,
    objectOrganization,
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
  if (type === 'Artifact' && input[graphQLType].file && isEmptyField(payload_bin)) {
    return artifactImport(context, user, { ...input, ...input[graphQLType] });
  }
  const observableInput = {
    stix_id,
    x_opencti_score,
    x_opencti_description,
    createdBy,
    objectMarking,
    objectOrganization,
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
    throw FunctionalError('Observable is not correctly formatted', { type, input: observableInput });
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
  const stixCyberObservable = await storeLoadById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
  if (!doesUserHaveAccess(user, 'KNOWLEDGE_KNUPDATE_KNDELETE', stixCyberObservable.entity_type)) {
    throw ForbiddenAccess();
  }
  await deleteElementById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
  return stixCyberObservableId;
};

// region relation ref
export const stixCyberObservableAddRelation = async (context, user, stixCyberObservableId, input) => {
  const stixCyberObservable = await storeLoadById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
  if (!doesUserHaveAccess(user, 'KNOWLEDGE_KNUPDATE_KNDELETE', stixCyberObservable.entity_type)) {
    throw ForbiddenAccess();
  }
  return stixObjectOrRelationshipAddRefRelation(context, user, stixCyberObservableId, input, ABSTRACT_STIX_CYBER_OBSERVABLE);
};
export const stixCyberObservableDeleteRelation = async (context, user, stixCyberObservableId, toId, relationshipType) => {
  const stixCyberObservable = await storeLoadById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
  if (!doesUserHaveAccess(user, 'KNOWLEDGE_KNUPDATE_KNDELETE', stixCyberObservable.entity_type)) {
    throw ForbiddenAccess();
  }
  return stixObjectOrRelationshipDeleteRefRelation(context, user, stixCyberObservableId, toId, relationshipType, ABSTRACT_STIX_CYBER_OBSERVABLE);
};
// endregion

export const stixCyberObservableEditField = async (context, user, stixCyberObservableId, input, opts = {}) => {
  const originalStixCyberObservable = await storeLoadById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
  if (!doesUserHaveAccess(user, 'KNOWLEDGE_KNUPDATE_KNDELETE', originalStixCyberObservable.entity_type)) {
    throw ForbiddenAccess();
  }
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
    const indicators = await listAllFromEntitiesThroughRelations(
      context,
      user,
      stixCyberObservableId,
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
  const { exportContext, format, exportType, maxMarkingDefinition, selectedIds } = args;
  const { search, orderBy, orderMode, filters, types } = args;
  const argsFilters = { search, orderBy, orderMode, filters, types };
  const ordersOpts = stixCyberObservableOptions.StixCyberObservablesOrdering;
  const listParams = exportTransformFilters(argsFilters, ordersOpts);
  const observableContext = { ...exportContext, entity_type: exportContext.entity_type ?? 'Stix-Cyber-Observable' };
  const works = await askListExport(context, user, observableContext, format, selectedIds, listParams, exportType, maxMarkingDefinition);
  return works.map((w) => workToExportFile(w));
};
export const stixCyberObservableExportAsk = async (context, user, stixCyberObservableId, args) => {
  const { format, exportType, maxMarkingDefinition = null } = args;
  const entity = await storeLoadById(context, user, stixCyberObservableId, ABSTRACT_STIX_CYBER_OBSERVABLE);
  const works = await askEntityExport(context, user, format, entity, exportType, maxMarkingDefinition);
  return works.map((w) => workToExportFile(w.work));
};
// endregion

// region mutation
export const stixCyberObservableDistribution = async (context, user, args) => {
  const { types = [ABSTRACT_STIX_CYBER_OBSERVABLE] } = args;
  return distributionEntities(context, user, types, args);
};

export const stixCyberObservableDistributionByEntity = async (context, user, args) => {
  const { relationship_type, objectId, types = [ABSTRACT_STIX_CYBER_OBSERVABLE] } = args;
  const filters = addFilter(args.filters, relationship_type.map((n) => buildRefRelationKey(n, '*')), objectId);
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

const extractInfectedZipFile = async (file) => {
  const buffer = await streamToBuffer(file.createReadStream());
  const directory = await unzipper.Open.buffer(buffer);
  const newFile = directory.files[0];
  const extracted = await newFile.buffer(nconf.get('app:artifact_zip_password'));
  const mimetype = await fileTypeFromBuffer(extracted);
  return { createReadStream: () => Readable.from(extracted), filename: newFile.path, mimetype: mimetype.mime };
};

export const artifactImport = async (context, user, args) => {
  const { file, x_opencti_description: description, createdBy, objectMarking, objectLabel } = args;
  let resolvedFile = await file;
  // Checking infected ZIP files
  try {
    resolvedFile = await extractInfectedZipFile(resolvedFile);
  } catch {
    // do nothing
  }
  const { createReadStream, filename, mimetype } = resolvedFile;
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
        { algorithm: 'SHA-512', hash: await checksumFile('sha512', createReadStream()) },
      ],
    },
    createdBy,
    objectMarking,
    objectLabel,
  };
  const artifact = await addStixCyberObservable(context, user, artifactData);
  const meta = { version };
  await upload(context, user, `import/${artifact.entity_type}/${artifact.id}`, resolvedFile, { entity: artifact, meta });
  return artifact;
};

export const indicatorsPaginated = async (context, user, stixCyberObservableId, args) => {
  return listEntitiesThroughRelationsPaginated(context, user, stixCyberObservableId, RELATION_BASED_ON, ENTITY_TYPE_INDICATOR, true, args);
};

export const vulnerabilitiesPaginated = async (context, user, stixCyberObservableId, args) => {
  return listEntitiesThroughRelationsPaginated(context, user, stixCyberObservableId, RELATION_HAS, ENTITY_TYPE_VULNERABILITY, false, args);
};

export const serviceDllsPaginated = async (context, user, stixCyberObservableId, args) => {
  return listEntitiesThroughRelationsPaginated(context, user, stixCyberObservableId, RELATION_SERVICE_DLL, ENTITY_HASHED_OBSERVABLE_STIX_FILE, false, args);
};

export const stixFileObsArtifact = async (context, user, stixCyberObservableId) => {
  return loadEntityThroughRelationsPaginated(context, user, stixCyberObservableId, RELATION_CONTENT, ENTITY_HASHED_OBSERVABLE_ARTIFACT, false);
};
