import { jsonToPlainText } from 'json-to-plain-text';
import { extractEntityRepresentativeName } from './entity-representative';
import { isStixObject } from '../schema/stixCoreObject';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE } from '../schema/stixCyberObservable';
import { isBasicRelationship } from '../schema/stixRelationship';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, isEmptyField, isNotEmptyField } from './utils';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { FROM_START_STR, truncate, UNTIL_END_STR } from '../utils/format';
import { authorizedMembers, creators as creatorsAttribute } from '../schema/attribute-definition';
import { X_WORKFLOW_ID } from '../schema/identifier';
import { isStoreRelationPir } from '../schema/internalRelationship';
import { pirExplanation } from '../modules/attributes/internalRelationship-registrationAttributes';
import { logApp } from '../config/conf';

export const generateMergeMessage = (instance, sources) => {
  const name = extractEntityRepresentativeName(instance);
  const sourcesNames = sources.map((source) => extractEntityRepresentativeName(source)).join(', ');
  return `merges ${instance.entity_type} \`${sourcesNames}\` in \`${name}\``;
};

const generateCreateDeleteMessage = (type, instance) => {
  const name = extractEntityRepresentativeName(instance);
  if (isStoreRelationPir(instance)) {
    const action = type === EVENT_TYPE_CREATE ? 'added to' : 'removed from';
    const from = extractEntityRepresentativeName(instance.from);
    const fromType = instance.from.entity_type;
    const to = extractEntityRepresentativeName(instance.to);
    const toType = instance.to.entity_type;
    return `${fromType} \`${from}\` ${action} ${toType} \`${to}\``;
  }
  if (isStixObject(instance.entity_type)) {
    let entityType = instance.entity_type;
    if (entityType === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
      entityType = 'File';
    }
    return `${type}s a ${entityType} \`${name}\``;
  }
  if (isBasicRelationship(instance.entity_type)) {
    const from = extractEntityRepresentativeName(instance.from);
    let fromType = instance.from.entity_type;
    if (fromType === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
      fromType = 'File';
    }
    const to = extractEntityRepresentativeName(instance.to);
    let toType = instance.to.entity_type;
    if (toType === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
      toType = 'File';
    }
    return `${type}s the relation ${instance.entity_type} from \`${from}\` (${fromType}) to \`${to}\` (${toType})`;
  }
  return '-';
};

export const generateCreateMessage = (instance) => {
  return generateCreateDeleteMessage(EVENT_TYPE_CREATE, instance);
};
export const generateDeleteMessage = (instance) => {
  return generateCreateDeleteMessage(EVENT_TYPE_DELETE, instance);
};
export const generateRestoreMessage = (instance) => {
  // this method is used only to generate a history message, there is no event restore in stream.
  return generateCreateDeleteMessage('restore', instance);
};

const ACTION_KEYS = ['x_opencti_request_access', pirExplanation.name];
export const MAX_PATCH_ELEMENTS_FOR_MESSAGE = 3;
export const MAX_OPERATIONS_FOR_MESSAGE = 3;
export const generateUpdatePatchMessage = (patchElements, entityType, data = {}) => {
  logApp.info('patchElements ===========', { patchElements });
  // noinspection UnnecessaryLocalVariableJS
  const generatedMessage = patchElements
    .slice(0, MAX_PATCH_ELEMENTS_FOR_MESSAGE).map(([type, operations]) => {
      return buildUpdateMessageForPatchOperations(type, operations, entityType, data);
    }).join(' | ');
  // Return generated update message
  return generatedMessage;
};

const getValuesArray = (value) => {
  const valuesFromArray = Array.isArray(value) ? value : [value];
  return valuesFromArray.filter((v) => isNotEmptyField(v));
};
const getKeyName = (entityType, key, object_path) => {
  let keyName;
  const relationsRefDefinition = schemaRelationsRefDefinition.getRelationRef(entityType, key);
  const attributeDefinition = schemaAttributesDefinition.getAttribute(entityType, key);
  if (relationsRefDefinition) {
    keyName = relationsRefDefinition.label ?? relationsRefDefinition.stixName;
  } else {
    keyName = object_path ?? attributeDefinition.label ?? attributeDefinition.name;
  }
  return keyName;
};

const buildMessageForCreatorsValues = (values, creators) => {
  if (creators?.length > 0) {
    return values.map((creatorId) => {
      const creator = creators.find((c) => c?.id === creatorId);
      return `${creator?.name ?? creatorId}`;
    }).join(', ');
  }
  return 'itself'; // Creator special case
};
const EMPTY_VALUE = 'nothing';
const buildMessageForValues = (entityType, key, values, data = {}, specificOperationCases = {}) => {
  if (isEmptyField(values)) {
    return EMPTY_VALUE;
  }
  const { members, creators } = data;
  const { actionRequestAccess } = specificOperationCases;
  const firstValues = values.slice(0, 3);
  const attributeDefinition = schemaAttributesDefinition.getAttribute(entityType, key);
  const relationsRefDefinition = schemaRelationsRefDefinition.getRelationRef(entityType, key);
  // If update is based on internal ref, we need to extract the value
  if (relationsRefDefinition) {
    return firstValues.map((val) => truncate(extractEntityRepresentativeName(val), 250)).join(', ');
  }
  if (key === creatorsAttribute.name) {
    return buildMessageForCreatorsValues(values, creators);
  }
  if (key === authorizedMembers.name) {
    return values.map(({ id, access_right }) => {
      const member = members.find(({ internal_id }) => internal_id === id);
      return `\`${member?.name ?? id} (${access_right})\``;
    }).join(', ');
  }
  if (key === X_WORKFLOW_ID) {
    if (actionRequestAccess) {
      const { status } = JSON.parse(actionRequestAccess.value[0]);
      return `${firstValues.join(', ')} (request access ${status})`;
    }
    return firstValues.join(', ');
  }
  if (attributeDefinition.type === 'string' && attributeDefinition.format === 'json') {
    return firstValues.map((v) => truncate(JSON.stringify(v), 250));
  }
  if (attributeDefinition.type === 'date') {
    return firstValues.map((v) => ((v === FROM_START_STR || v === UNTIL_END_STR) ? EMPTY_VALUE : v));
  }
  if (attributeDefinition.type === 'object') {
    return jsonToPlainText(firstValues, { spacing: false });
  }
  // If standard primitive data, just join the values
  return firstValues.join(', ');
};
const MAX_DISPLAYED_VALUES = 3;
const buildUpdateMessageForPatchOperation = (operationType, patchOperation, entityType, data = {}, specificOperationCases = {}) => {
  const { key, value, object_path, previous } = patchOperation;
  const keyName = getKeyName(entityType, key, object_path);
  const valuesArray = getValuesArray(value); // TODO we need the whole values
  const previousArray = getValuesArray(previous);
  const messageForValues = buildMessageForValues(entityType, key, valuesArray, data, specificOperationCases);
  const messageForPrevious = buildMessageForValues(entityType, key, previousArray, data, specificOperationCases);

  let message = `\`${messageForValues}\``;
  if (operationType === 'replace') {
    message = `\`${messageForPrevious}\` with \`${messageForValues}\``;
  }
  message += ` in \`${keyName}\``;
  if (valuesArray.length > MAX_DISPLAYED_VALUES) {
    message += ` and ${valuesArray.length - MAX_DISPLAYED_VALUES} more items`; // TODO should be tested on the whole values
  }
  return message;
};

const buildUpdateMessageForPatchOperations = (operationType, patchOperations, entityType, data = {}) => {
  const filteredOperations = patchOperations.filter((op) => !ACTION_KEYS.includes(op.key));
  const slicedOperations = filteredOperations.slice(0, MAX_OPERATIONS_FOR_MESSAGE);
  const actionRequestAccess = patchOperations.find((op) => op.key === 'x_opencti_request_access');
  const specificOperationCases = { actionRequestAccess };
  const messages = slicedOperations.map((op) => buildUpdateMessageForPatchOperation(operationType, op, entityType, data, specificOperationCases));
  return `${operationType}s ${messages.join(' - ')}${filteredOperations.length > 3 ? ` and ${filteredOperations.length - 3} more operations` : ''}`;
};
