import { jsonToPlainText } from 'json-to-plain-text';
import { extractEntityRepresentativeName } from './entity-representative';
import { isStixObject } from '../schema/stixCoreObject';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE } from '../schema/stixCyberObservable';
import { isBasicRelationship } from '../schema/stixRelationship';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, isNotEmptyField } from './utils';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { FROM_START_STR, truncate, UNTIL_END_STR } from '../utils/format';
import { authorizedMembers, creators as creatorsAttribute } from '../schema/attribute-definition';
import { X_WORKFLOW_ID } from '../schema/identifier';
import { isStoreRelationPir } from '../schema/internalRelationship';
import { pirExplanation } from '../modules/attributes/internalRelationship-registrationAttributes';

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
  const { members, creators } = data;
  // noinspection UnnecessaryLocalVariableJS
  const generatedMessage = patchElements
    .slice(0, MAX_PATCH_ELEMENTS_FOR_MESSAGE).map(([type, operations]) => {
      const actionRequestAccess = operations.find((op) => op.key === 'x_opencti_request_access');
      const pirExplanations = operations.find((op) => op.key === pirExplanation.name);
      const filteredOperations = operations.filter((op) => !ACTION_KEYS.includes(op.key));
      return `${type}s ${filteredOperations
        .slice(0, MAX_OPERATIONS_FOR_MESSAGE).map(({ key, value, object_path, previous }) => {
          let message = 'nothing';
          let convertedKey;
          const relationsRefDefinition = schemaRelationsRefDefinition.getRelationRef(entityType, key);
          const attributeDefinition = schemaAttributesDefinition.getAttribute(entityType, key);
          if (relationsRefDefinition) {
            convertedKey = relationsRefDefinition.label ?? relationsRefDefinition.stixName;
          } else {
            convertedKey = object_path ?? attributeDefinition.label ?? attributeDefinition.name;
          }
          const fromArray = Array.isArray(value) ? value : [value];
          const values = fromArray.slice(0, 3).filter((v) => isNotEmptyField(v));
          if (key === 'pir_score' && type === 'replace' && pirExplanations) {
            // case in-pir relationship update: the message should only display the variation of score
            const previousArray = Array.isArray(previous) ? previous : [previous];
            return `\`${previousArray.join(', ')}\` to \`${values.join(', ')}\` in \`${convertedKey}\``;
          }
          if (isNotEmptyField(values)) {
            // If update is based on internal ref, we need to extract the value
            if (relationsRefDefinition) {
              message = values.map((val) => truncate(extractEntityRepresentativeName(val), 250)).join(', ');
            } else if (key === creatorsAttribute.name) {
              if (creators?.length > 0) {
                message = value.map((creatorId) => {
                  const creator = creators.find((c) => c?.id === creatorId);
                  return `${creator?.name ?? creatorId}`;
                }).join(', ');
              } else {
                message = 'itself'; // Creator special case
              }
            } else if (key === X_WORKFLOW_ID) {
              if (actionRequestAccess) {
                const { status } = JSON.parse(actionRequestAccess.value[0]);
                message = `${values.join(', ')} (request access ${status})`;
              } else {
                message = values.join(', ');
              }
            } else if (key === authorizedMembers.name) {
              message = value.map(({ id, access_right }) => {
                const member = members.find(({ internal_id }) => internal_id === id);
                return `${member?.name ?? id} (${access_right})`;
              }).join(', ');
            } else if (attributeDefinition.type === 'string' && attributeDefinition.format === 'json') {
              message = values.map((v) => truncate(JSON.stringify(v), 250));
            } else if (attributeDefinition.type === 'date') {
              message = values.map((v) => ((v === FROM_START_STR || v === UNTIL_END_STR) ? 'nothing' : v));
            } else if (attributeDefinition.type === 'object') {
              message = jsonToPlainText(values, { spacing: false });
            } else {
              // If standard primitive data, just join the values
              message = values.join(', ');
            }
          }
          return `\`${message}\` in \`${convertedKey}\`${(fromArray.length > 3) ? ` and ${fromArray.length - 3} more items` : ''}`;
        }).join(' - ')}${filteredOperations.length > 3 ? ` and ${filteredOperations.length - 3} more operations` : ''}`;
    }).join(' | ');
  // Return generated update message
  return generatedMessage;
};
