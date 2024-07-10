import * as R from 'ramda';
import {
  BASE_TYPE_ENTITY,
  BASE_TYPE_RELATION,
  ID_INTERNAL,
  ID_STANDARD,
  IDS_STIX,
  INPUT_ASSIGNEE,
  INPUT_CREATED_BY,
  INPUT_GRANTED_REFS,
  INPUT_KILLCHAIN,
  INPUT_LABELS,
  INPUT_MARKINGS,
  INPUT_PARTICIPANT,
  INTERNAL_IDS_ALIASES
} from '../schema/general';
import { getParentTypes } from '../schema/schemaUtils';
import { generateAliasesIdsForInstance, generateInternalId, generateStandardId, normalizeName, X_WORKFLOW_ID } from '../schema/identifier';
import { FROM_START, now, UNTIL_END } from '../utils/format';
import { inferIndexFromConceptType, isEmptyField, isNotEmptyField } from './utils';
import { isStixRelationshipExceptRef } from '../schema/stixRelationship';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { DatabaseError } from '../config/errors';
import {
  isStixRefRelationship,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_GRANTED_TO,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING
} from '../schema/stixRefRelationship';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { ENTITY_TYPE_STATUS, isDatedInternalObject } from '../schema/internalObject';
import { isStixObject } from '../schema/stixCoreObject';
import { isStixMetaObject } from '../schema/stixMetaObject';
import { isStixDomainObject, isStixObjectAliased, resolveAliasesField, STIX_ORGANIZATIONS_RESTRICTED, STIX_ORGANIZATIONS_UNRESTRICTED } from '../schema/stixDomainObject';
import { getEntitiesListFromCache } from './cache';
import { isUserHasCapability, KNOWLEDGE_ORGANIZATION_RESTRICT } from '../utils/access';
import { cleanMarkings } from '../utils/markingDefinition-utils';

export const LIST_REFS = [INPUT_PARTICIPANT, INPUT_ASSIGNEE, INPUT_KILLCHAIN, INPUT_CREATED_BY, INPUT_LABELS, INPUT_GRANTED_REFS, INPUT_MARKINGS];

export const buildEntityData = async (context, user, input, type, opts = {}) => {
  const { fromRule } = opts;
  const internalId = input.internal_id || generateInternalId();
  const standardId = input.standard_id || generateStandardId(type, input);
  // Complete with identifiers
  const today = now();
  const inferred = isNotEmptyField(fromRule);
  // Default attributes
  let data = R.pipe(
    R.assoc('_index', inferIndexFromConceptType(type, inferred)),
    R.assoc(ID_INTERNAL, internalId),
    R.assoc(ID_STANDARD, standardId),
    R.assoc('entity_type', type),
    R.assoc('element_to_denorm', 'element'),
    R.assoc('creator_id', [user.internal_id]),
    R.dissoc('update'),
    R.dissoc('file'),
    R.omit(schemaRelationsRefDefinition.getInputNames(input.entity_type)),
  )(input);
  if (inferred) {
    // Simply add the rule
    // start/stop confidence was computed by the rule directly
    data[fromRule] = input[fromRule];
  }
  // Some internal objects have dates
  if (isDatedInternalObject(type)) {
    data = R.pipe(R.assoc('created_at', today), R.assoc('updated_at', today))(data);
  }
  // Stix-Object
  if (isStixObject(type)) {
    const stixIds = input.x_opencti_stix_ids || [];
    const haveStixId = isNotEmptyField(input.stix_id);
    if (haveStixId && input.stix_id !== standardId) {
      stixIds.push(input.stix_id.toLowerCase());
    }
    data = R.pipe(
      R.assoc(IDS_STIX, stixIds),
      R.dissoc('stix_id'),
      R.assoc('created_at', today),
      R.assoc('updated_at', today)
    )(data);
  }
  // Stix-Meta-Object
  if (isStixMetaObject(type)) {
    data = R.pipe(
      R.assoc('created', R.isNil(input.created) ? today : input.created),
      R.assoc('modified', R.isNil(input.modified) ? today : input.modified)
    )(data);
  }
  // STIX-Core-Object
  // -- STIX-Domain-Object
  if (isStixDomainObject(type)) {
    data = R.pipe(
      R.assoc('revoked', R.isNil(input.revoked) ? false : input.revoked),
      R.assoc('confidence', R.isNil(input.confidence) ? 0 : input.confidence),
      R.assoc('lang', R.isNil(input.lang) ? 'en' : input.lang),
      R.assoc('created', R.isNil(input.created) ? today : input.created),
      R.assoc('modified', R.isNil(input.modified) ? today : input.modified)
    )(data);
    // Get statuses
    const platformStatuses = await getEntitiesListFromCache(context, user, ENTITY_TYPE_STATUS);
    const statusesForType = platformStatuses.filter((p) => p.type === type);
    if (statusesForType.length > 0) {
      // Check, if status is not set or not valid
      if (R.isNil(input[X_WORKFLOW_ID]) || statusesForType.filter((n) => n.id === input[X_WORKFLOW_ID]).length === 0) {
        data = R.assoc(X_WORKFLOW_ID, R.head(statusesForType).id, data);
      }
    }
  }
  // -- Aliased entities
  if (isStixObjectAliased(type)) {
    const aliasField = resolveAliasesField(type).name;
    if (input[aliasField]) {
      const preparedAliases = input[aliasField].filter((a) => isNotEmptyField(a)).map((a) => a.trim());
      const uniqAliases = R.uniqBy((e) => normalizeName(e), preparedAliases);
      data[aliasField] = uniqAliases.filter((e) => normalizeName(e) !== normalizeName(input.name));
    }
    const aliasIds = generateAliasesIdsForInstance(data);
    data[INTERNAL_IDS_ALIASES] = aliasIds;
    // Do not cumulate alias standard IDs in other STIX IDs
    if (data[IDS_STIX]) {
      data[IDS_STIX] = data[IDS_STIX].filter((id) => !aliasIds.includes(id));
    }
  }
  // Create the meta relationships (ref, refs)
  const relToCreate = [];
  const isSegregationEntity = !STIX_ORGANIZATIONS_UNRESTRICTED.some((o) => getParentTypes(data.entity_type).includes(o))
    || STIX_ORGANIZATIONS_RESTRICTED.some((o) => o === data.entity_type || getParentTypes(data.entity_type).includes(o));
  const appendMetaRelationships = async (inputField, relType) => {
    if (input[inputField] || relType === RELATION_GRANTED_TO) {
      // For organizations management
      if (relType === RELATION_GRANTED_TO && isSegregationEntity) {
        const grants = input[INPUT_GRANTED_REFS] ?? [];
        if (isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT) && input[inputField]
              && (!Array.isArray(input[inputField]) || input[inputField].length > 0)) {
          const targets = Array.isArray(grants) ? grants : [grants];
          relToCreate.push(...buildInnerRelation(data, input[inputField], RELATION_GRANTED_TO));
          data['rel_granted.internal_id'] = (targets ?? []).map((m) => m.internal_id);
        } else if (!user.inside_platform_organization) {
          // If user is not part of the platform organization, put its own organizations
          const targets = Array.isArray(grants) ? grants : [grants];
          relToCreate.push(...buildInnerRelation(data, user.organizations, RELATION_GRANTED_TO));
          data['rel_granted.internal_id'] = (targets ?? []).map((m) => m.internal_id);
        }
      } else if (relType === RELATION_OBJECT_MARKING) {
        const markingsFiltered = await cleanMarkings(context, input[inputField]);
        relToCreate.push(...buildInnerRelation(data, markingsFiltered, relType));
        data['rel_object-marking.internal_id'] = (markingsFiltered ?? []).map((m) => m.internal_id);
      } else if (input[inputField]) {
        const instancesToCreate = Array.isArray(input[inputField]) ? input[inputField] : [input[inputField]];
        if (LIST_REFS.includes(inputField)) {
          data[`rel_${relType}.internal_id`] = (instancesToCreate ?? []).map((m) => m.internal_id);
        }
        relToCreate.push(...buildInnerRelation(data, instancesToCreate, relType));
      }
    }
  };
  // For meta stix core && meta observables
  const inputFields = schemaRelationsRefDefinition.getRelationsRef(input.entity_type);
  for (let fieldIndex = 0; fieldIndex < inputFields.length; fieldIndex += 1) {
    const inputField = inputFields[fieldIndex];
    await appendMetaRelationships(inputField.name, inputField.databaseName);
  }

  // Transaction succeed, complete the result to send it back
  const entity = R.pipe(
    R.assoc('id', internalId),
    R.assoc('base_type', BASE_TYPE_ENTITY),
    R.assoc('parent_types', getParentTypes(type))
  )(data);

  // Simply return the data
  return {
    isCreation: true,
    element: entity,
    previous: null,
    relations: relToCreate, // Added meta relationships
  };
};

export const buildRelationData = async (context, user, input, opts = {}) => {
  const { fromRule } = opts;
  const { from, to, relationship_type: relationshipType } = input;
  // 01. Generate the ID
  const internalId = input.internal_id || generateInternalId();
  const standardId = input.standard_id || generateStandardId(relationshipType, input);
  // 02. Prepare the relation to be created
  const today = now();
  const fromRole = `${relationshipType}_from`;
  const toRole = `${relationshipType}_to`;
  const data = {};
  // Default attributes
  // basic-relationship
  const inferred = isNotEmptyField(fromRule);
  data._index = inferIndexFromConceptType(relationshipType, inferred);
  if (inferred) {
    // Simply add the rule
    // start/stop confidence was computed by the rule directly
    data[fromRule] = input[fromRule];
    data.i_inference_weight = input.i_inference_weight;
  }
  data.internal_id = internalId;
  data.element_to_denorm = 'element';
  // data.element_to_denorm = { name: 'denorm', parent: from.internal_id };
  // data.denorm_id = to.internal_id;
  // data.denorm_role = toRole;
  // data.denorm_type = relationshipType;
  // data.element_to_source = { name: 'source', parent: from.internal_id };
  // data.element_to_target = { name: 'target', parent: to.internal_id };
  data.standard_id = standardId;
  data.entity_type = relationshipType;
  data.relationship_type = relationshipType;
  data.creator_id = [user.internal_id];
  data.created_at = today;
  data.updated_at = today;
  // region re-work data
  // stix-relationship
  if (isStixRelationshipExceptRef(relationshipType)) {
    const stixIds = input.x_opencti_stix_ids || [];
    const haveStixId = isNotEmptyField(input.stix_id);
    if (haveStixId && input.stix_id !== standardId) {
      stixIds.push(input.stix_id.toLowerCase());
    }
    data.x_opencti_stix_ids = stixIds;
    data.revoked = R.isNil(input.revoked) ? false : input.revoked;
    data.confidence = R.isNil(input.confidence) ? 0 : input.confidence;
    data.lang = R.isNil(input.lang) ? 'en' : input.lang;
    data.created = R.isNil(input.created) ? today : input.created;
    data.modified = R.isNil(input.modified) ? today : input.modified;
    // Get statuses
    let type = null;
    if (isStixCoreRelationship(relationshipType)) {
      type = 'stix-core-relationship';
    } else if (isStixSightingRelationship(relationshipType)) {
      type = 'stix-sighting-relationship';
    }
    if (type) {
      // Get statuses
      const platformStatuses = await getEntitiesListFromCache(context, user, ENTITY_TYPE_STATUS);
      const statusesForType = platformStatuses.filter((p) => p.type === type);
      if (statusesForType.length > 0) {
        // Check, if status is not set or not valid
        if (R.isNil(input[X_WORKFLOW_ID]) || statusesForType.filter((n) => n.id === input[X_WORKFLOW_ID]).length === 0) {
          data[X_WORKFLOW_ID] = R.head(statusesForType).id;
        }
      }
    }
  }
  // stix-ref-relationship
  if (isStixRefRelationship(relationshipType) && schemaRelationsRefDefinition.isDatable(from.entity_type, relationshipType)) {
    // because spec is only put in all stix except meta, and stix cyber observable is a meta but requires this
    data.start_time = R.isNil(input.start_time) ? new Date(FROM_START) : input.start_time;
    data.stop_time = R.isNil(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
    data.created = R.isNil(input.created) ? today : input.created;
    data.modified = R.isNil(input.modified) ? today : input.modified;
    //* v8 ignore if */
    if (data.start_time > data.stop_time) {
      throw DatabaseError('You cant create a relation with a stop_time less than the start_time', {
        from: input.fromId,
        to: input.toId,
        type: relationshipType
      });
    }
  }
  // stix-core-relationship
  if (isStixCoreRelationship(relationshipType)) {
    data.description = input.description ? input.description : '';
    data.start_time = isEmptyField(input.start_time) ? new Date(FROM_START) : input.start_time;
    data.stop_time = isEmptyField(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
    //* v8 ignore if */
    if (data.start_time > data.stop_time) {
      throw DatabaseError('You cant create a relation with a stop_time less than the start_time', {
        from: input.fromId,
        to: input.toId,
        type: relationshipType
      });
    }
  }
  // stix-sighting-relationship
  if (isStixSightingRelationship(relationshipType)) {
    data.description = R.isNil(input.description) ? '' : input.description;
    data.attribute_count = R.isNil(input.attribute_count) ? 1 : input.attribute_count;
    data.x_opencti_negative = R.isNil(input.x_opencti_negative) ? false : input.x_opencti_negative;
    data.first_seen = R.isNil(input.first_seen) ? new Date(FROM_START) : input.first_seen;
    data.last_seen = R.isNil(input.last_seen) ? new Date(UNTIL_END) : input.last_seen;
    //* v8 ignore if */
    if (data.first_seen > data.last_seen) {
      throw DatabaseError('You cant create a relation with last_seen less than first_seen', {
        from: input.fromId,
        to: input.toId,
        type: relationshipType
      });
    }
  }
  // endregion
  // 04. Create the relation
  // Build final query
  const relToCreate = [];
  if (isStixRelationshipExceptRef(relationshipType)) {
    // We need to link the data to organization sharing, only for core and sightings.
    const grants = input[INPUT_GRANTED_REFS] ?? [];
    if (isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT) && input[INPUT_GRANTED_REFS]
          && (!Array.isArray(input[INPUT_GRANTED_REFS]) || input[INPUT_GRANTED_REFS].length > 0)) {
      const targets = Array.isArray(grants) ? grants : [grants];
      relToCreate.push(...buildInnerRelation(data, input[INPUT_GRANTED_REFS], RELATION_GRANTED_TO));
      data['rel_granted.internal_id'] = (targets ?? []).map((m) => m.internal_id);
    } else if (!user.inside_platform_organization) {
      // If user is not part of the platform organization, put its own organizations
      relToCreate.push(...buildInnerRelation(data, user.organizations, RELATION_GRANTED_TO));
      const targets = Array.isArray(grants) ? grants : [grants];
      data['rel_granted.internal_id'] = (targets ?? []).map((m) => m.internal_id);
    }
    const markingsFiltered = await cleanMarkings(context, input.objectMarking);
    relToCreate.push(...buildInnerRelation(data, markingsFiltered, RELATION_OBJECT_MARKING));
    data['rel_object-marking.internal_id'] = (markingsFiltered ?? []).map((m) => m.internal_id);
  }
  const createdBy = input.createdBy ?? [];
  const createdByArrays = Array.isArray(createdBy) ? createdBy : [createdBy];
  if (isStixCoreRelationship(relationshipType)) {
    relToCreate.push(...buildInnerRelation(data, input.createdBy, RELATION_CREATED_BY));
    data['rel_created-by.internal_id'] = (createdByArrays ?? []).map((m) => m.internal_id);
    relToCreate.push(...buildInnerRelation(data, input.objectLabel, RELATION_OBJECT_LABEL));
    const objectLabel = input.objectLabel ?? [];
    const objectLabelArrays = Array.isArray(objectLabel) ? objectLabel : [objectLabel];
    data['rel_object-label.internal_id'] = (objectLabelArrays ?? []).map((m) => m.internal_id);
    relToCreate.push(...buildInnerRelation(data, input.killChainPhases, RELATION_KILL_CHAIN_PHASE));
    // data['rel_kill-chain-phase.internal_id'] = (input.objectLabel ?? []).map((m) => m.internal_id);
    relToCreate.push(...buildInnerRelation(data, input.externalReferences, RELATION_EXTERNAL_REFERENCE));
    // data['rel_external-reference.internal_id'] = (input.objectLabel ?? []).map((m) => m.internal_id);
  }
  if (isStixSightingRelationship(relationshipType)) {
    relToCreate.push(...buildInnerRelation(data, input.createdBy, RELATION_CREATED_BY));
    data['rel_created-by.internal_id'] = (createdByArrays ?? []).map((m) => m.internal_id);
  }
  // 05. Prepare the final data
  const created = R.pipe(
    R.assoc('id', internalId),
    R.assoc('from', from),
    R.assoc('fromId', from.internal_id),
    R.assoc('fromRole', fromRole),
    R.assoc('fromType', from.entity_type),
    R.assoc('to', to),
    R.assoc('toId', to.internal_id),
    R.assoc('toRole', toRole),
    R.assoc('toType', to.entity_type),
    R.assoc('entity_type', relationshipType),
    R.assoc('parent_types', getParentTypes(relationshipType)),
    R.assoc('base_type', BASE_TYPE_RELATION)
  )(data);
  // 06. Return result if no need to reverse the relations from and to
  return {
    element: created,
    isCreation: true,
    previous: null,
    relations: relToCreate
  };
};

const buildRelationInput = (input) => {
  const { from, relationship_type: relationshipType } = input;
  // 03. Generate the ID
  const internalId = input.internal_id || generateInternalId();
  const standardId = input.standard_id || generateStandardId(relationshipType, input);
  // 05. Prepare the relation to be created
  const today = now();
  const relationAttributes = {};
  relationAttributes._index = inferIndexFromConceptType(relationshipType);
  // basic-relationship
  relationAttributes.internal_id = internalId;
  relationAttributes.standard_id = standardId;
  relationAttributes.entity_type = relationshipType;
  relationAttributes.relationship_type = relationshipType;
  relationAttributes.created_at = today;
  relationAttributes.updated_at = today;
  // stix-relationship
  if (isStixRelationshipExceptRef(relationshipType)) {
    const stixIds = input.x_opencti_stix_ids || [];
    const haveStixId = isNotEmptyField(input.stix_id);
    if (haveStixId && input.stix_id !== standardId) {
      stixIds.push(input.stix_id.toLowerCase());
    }
    relationAttributes.x_opencti_stix_ids = stixIds;
    relationAttributes.revoked = R.isNil(input.revoked) ? false : input.revoked;
    relationAttributes.confidence = R.isNil(input.confidence) ? 0 : input.confidence;
    relationAttributes.lang = R.isNil(input.lang) ? 'en' : input.lang;
    relationAttributes.created = R.isNil(input.created) ? today : input.created;
    relationAttributes.modified = R.isNil(input.modified) ? today : input.modified;
  }
  // stix-core-relationship
  if (isStixCoreRelationship(relationshipType)) {
    relationAttributes.description = R.isNil(input.description) ? null : input.description;
    relationAttributes.start_time = R.isNil(input.start_time) ? new Date(FROM_START) : input.start_time;
    relationAttributes.stop_time = R.isNil(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
    //* v8 ignore if */
    if (relationAttributes.start_time > relationAttributes.stop_time) {
      throw DatabaseError('You cant create a relation with stop_time less than start_time', {
        from: input.fromId,
        to: input.toId,
        type: relationshipType
      });
    }
  }
  // stix-ref-relationship
  if (isStixRefRelationship(relationshipType) && schemaRelationsRefDefinition.isDatable(from.entity_type, relationshipType)) {
    relationAttributes.start_time = R.isNil(input.start_time) ? new Date(FROM_START) : input.start_time;
    relationAttributes.stop_time = R.isNil(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
    relationAttributes.created = R.isNil(input.created) ? today : input.created;
    relationAttributes.modified = R.isNil(input.modified) ? today : input.modified;
    //* v8 ignore if */
    if (relationAttributes.start_time > relationAttributes.stop_time) {
      throw DatabaseError('You cant create a relation with stop_time less than start_time', {
        from: input.fromId,
        to: input.toId,
        type: relationshipType
      });
    }
  }
  // stix-sighting-relationship
  if (isStixSightingRelationship(relationshipType)) {
    relationAttributes.description = R.isNil(input.description) ? null : input.description;
    relationAttributes.attribute_count = R.isNil(input.attribute_count) ? 1 : input.attribute_count;
    relationAttributes.x_opencti_negative = R.isNil(input.x_opencti_negative) ? false : input.x_opencti_negative;
    relationAttributes.first_seen = R.isNil(input.first_seen) ? new Date(FROM_START) : input.first_seen;
    relationAttributes.last_seen = R.isNil(input.last_seen) ? new Date(UNTIL_END) : input.last_seen;
    //* v8 ignore if */
    if (relationAttributes.first_seen > relationAttributes.last_seen) {
      throw DatabaseError('You cant create a relation with a first_seen greater than the last_seen', {
        from: input.fromId,
        to: input.toId,
        type: relationshipType
      });
    }
  }
  return { relation: relationAttributes };
};

export const buildInnerRelation = (from, to, type) => {
  const targets = Array.isArray(to) ? to : [to];
  if (!to || R.isEmpty(targets)) {
    return [];
  }
  const relations = [];
  for (let i = 0; i < targets.length; i += 1) {
    const target = targets[i];
    const input = { from, to: target, relationship_type: type };
    const { relation } = buildRelationInput(input);
    // Ignore self relationships
    if (from.internal_id !== target.internal_id) {
      const basicRelation = {
        id: relation.internal_id,
        from,
        fromId: from.internal_id,
        fromRole: `${type}_from`,
        fromType: from.entity_type,
        to: target,
        toId: target.internal_id,
        toRole: `${type}_to`,
        toType: target.entity_type,
        base_type: BASE_TYPE_RELATION,
        parent_types: getParentTypes(relation.entity_type),
        ...relation,
      };
      relations.push(basicRelation);
    }
  }
  return relations;
};
