import * as R from 'ramda';
import { jsonToPlainText } from 'json-to-plain-text';
import { extractEntityRepresentativeName } from './entity-representative';
import { isStixObject } from '../schema/stixCoreObject';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE } from '../schema/stixCyberObservable';
import { isBasicRelationship } from '../schema/stixRelationship';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, isNotEmptyField, UPDATE_OPERATION_REPLACE } from './utils';
import { UnsupportedError } from '../config/errors';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { isDateAttribute, isJsonAttribute, isObjectAttribute, schemaAttributesDefinition } from '../schema/schema-attributes';
import { truncate } from '../utils/mailData';
import { creators } from '../schema/attribute-definition';
import { FROM_START_STR, UNTIL_END_STR } from '../utils/format';
import { SYSTEM_USER } from '../utils/access';
import { internalFindByIds } from './middleware-loader';

export const generateMergeMessage = (instance, sources) => {
  const name = extractEntityRepresentativeName(instance);
  const sourcesNames = sources.map((source) => extractEntityRepresentativeName(source)).join(', ');
  return `merges ${instance.entity_type} \`${sourcesNames}\` in \`${name}\``;
};

const generateCreateDeleteMessage = (type, instance) => {
  const name = extractEntityRepresentativeName(instance);
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

export const generateUpdateMessage = async (context, entityType, inputs) => {
  const inputsByOperations = R.groupBy((m) => m.operation ?? UPDATE_OPERATION_REPLACE, inputs);
  const patchElements = Object.entries(inputsByOperations);
  if (patchElements.length === 0) {
    throw UnsupportedError('Generating update message with empty inputs fail');
  }

  const authorizedMembersIds = patchElements.slice(0, 3).flatMap(([,operations]) => {
    return operations.slice(0, 3).flatMap(({ key, value }) => {
      return key === 'authorized_members' ? (value ?? []).map(({ id }) => id) : [];
    });
  });
  let members = [];
  if (authorizedMembersIds.length > 0) {
    members = await internalFindByIds(context, SYSTEM_USER, authorizedMembersIds, {
      baseData: true,
      baseFields: ['internal_id', 'name']
    });
  }

  // noinspection UnnecessaryLocalVariableJS
  const generatedMessage = patchElements.slice(0, 3).map(([type, operations]) => {
    return `${type}s ${operations.slice(0, 3).map(({ key, value }) => {
      let message = 'nothing';
      let convertedKey;
      const relationsRefDefinition = schemaRelationsRefDefinition.getRelationRef(entityType, key);
      if (relationsRefDefinition) {
        convertedKey = relationsRefDefinition.label ?? relationsRefDefinition.stixName;
      } else {
        const attributeDefinition = schemaAttributesDefinition.getAttribute(entityType, key);
        convertedKey = attributeDefinition.label ?? attributeDefinition.name;
      }
      const fromArray = Array.isArray(value) ? value : [value];
      const values = fromArray.slice(0, 3).filter((v) => isNotEmptyField(v));
      if (isNotEmptyField(values)) {
        // If update is based on internal ref, we need to extract the value
        if (relationsRefDefinition) {
          message = values.map((val) => truncate(extractEntityRepresentativeName(val))).join(', ');
        } else if (key === creators.name) {
          message = 'itself'; // Creator special case
        } else if (key === 'authorized_members') {
          message = value.map(({ id, access_right }) => {
            const member = members.find(({ internal_id }) => internal_id === id);
            return `${member?.name ?? id} (${access_right})`;
          }).join(', ');
        } else if (isJsonAttribute(key)) {
          message = values.map((v) => truncate(JSON.stringify(v)));
        } else if (isDateAttribute(key)) {
          message = values.map((v) => ((v === FROM_START_STR || v === UNTIL_END_STR) ? 'nothing' : v));
        } else if (isObjectAttribute(key)) {
          message = jsonToPlainText(values, { color: false, spacing: false });
        } else {
          // If standard primitive data, just join the values
          message = values.join(', ');
        }
      }
      return `\`${message}\` in \`${convertedKey}\`${(fromArray.length > 3) ? ` and ${fromArray.length - 3} more items` : ''}`;
    }).join(' - ')}`;
  }).join(' | ');
  // Return generated update message
  return `${generatedMessage}${patchElements.length > 3 ? ` and ${patchElements.length - 3} more operations` : ''}`;
};
