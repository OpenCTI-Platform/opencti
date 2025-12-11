import { type BasicStoreEntityDeleteOperation, ENTITY_TYPE_DELETE_OPERATION } from './deleteOperation-types';
import { FunctionalError, LockTimeoutError, TYPE_LOCK_ERROR } from '../../config/errors';
import { elDeleteElements, elDeleteInstances, elFindByIds } from '../../database/engine';
import { deleteAllObjectFiles } from '../../database/file-storage';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { INDEX_DELETED_OBJECTS, isNotEmptyField, READ_INDEX_DELETED_OBJECTS } from '../../database/utils';
import { FilterMode, FilterOperator, OrderingMode, type QueryDeleteOperationsArgs } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import { controlUserConfidenceAgainstElement } from '../../utils/confidence-level';
import { prepareDate } from '../../utils/format';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { createEntity, createInferredRelation, createRelation, getExistingEntities, getExistingRelations } from '../../database/middleware';
import type { BasicStoreObject, BasicStoreRelation } from '../../types/store';
import { isStixRelationship } from '../../schema/stixRelationship';
import { isStixObject } from '../../schema/stixCoreObject';
import { elUpdateRemovedFiles } from '../../database/file-search';
import { logApp } from '../../config/conf';
import { extractRepresentative } from '../../database/entity-representative';
import { isStixSightingRelationship } from '../../schema/stixSightingRelationship';
import { lockResources } from '../../lock/master-lock';
import { RULE_PREFIX } from '../../schema/general';
import { createRuleContent } from '../../rules/rules-utils';
import { controlUserRestrictDeleteAgainstElement } from '../../utils/access';

type ConfirmDeleteOptions = {
  isRestoring?: boolean
};

//----------------------------------------------------------------------------------------------------------------------
// Utilities

/**
 * Picks the given keys from an object ; if key does not exist it's ignored
 */
const pick = (object: any, keys: string[] = []) => {
  return keys.reduce((acc, key) => {
    if (isNotEmptyField(object[key])) {
      acc[key] = object[key];
    }
    return acc;
  }, {} as Record<string, any>);
};

/**
 * Convert an element as stored in database to an input for the createEntity / createRelation middleware functions
 */
const convertStoreEntityToInput = (element: BasicStoreObject, upsertedElements: Record<string, string> = {}) => {
  const { entity_type } = element;
  // forge input from the object in DB, as we want to "create" the element to trigger the full chain of events
  // start with the attributes defined in schema
  const availableAttributes = Array.from(schemaAttributesDefinition.getAttributes(entity_type).values());
  const availableAttributeNames = availableAttributes.map((attr) => attr.name);
  const directInputs = pick(element, availableAttributeNames);

  // We need all refs that have 'From' as the main entity ; we can rely on the schema
  // add refs registered for this type using inverse mapping database name <> attribute name
  // for instance created-by in DB shall be createdBy in the input object
  const availableRefAttributes = schemaRelationsRefDefinition.getRelationsRef(entity_type);
  const availableRefAttributesDatabaseNames = availableRefAttributes.map((attr) => attr.databaseName);
  const refsInElement = pick(element, availableRefAttributesDatabaseNames);
  const refInputs: any = {};
  Object.keys(refsInElement).forEach((refDbName) => {
    const key = schemaRelationsRefDefinition.convertDatabaseNameToInputName(entity_type, refDbName) as string; // cannot be null by design
    refInputs[key] = refsInElement[refDbName];
  });

  if (isStixObject(entity_type)) {
    return {
      ...directInputs,
      ...refInputs
    };
  }
  if (isStixRelationship(entity_type)) {
    const connectionInput = pick(element, ['fromId', 'toId']);
    if (connectionInput.fromId && upsertedElements[connectionInput.fromId] !== undefined) {
      connectionInput.fromId = upsertedElements[connectionInput.fromId];
    }
    if (connectionInput.toId && upsertedElements[connectionInput.toId] !== undefined) {
      connectionInput.toId = upsertedElements[connectionInput.toId];
    }

    return {
      ...directInputs,
      ...refInputs,
      ...connectionInput,
    };
  }
  throw FunctionalError('Could not convert element to input for DeleteOperation restore', { entity_type });
};

/**
 * Resolve the elements to restore inside a DeleteOperation, throws an error if it's impossible to fully restore the cluster
 *
 */
const resolveEntitiesToRestore = async (context: AuthContext, user: AuthUser, deleteOperation: BasicStoreEntityDeleteOperation) => {
  // check that the element cluster can be fully restored, throw error otherwise
  const { main_entity_id, main_entity_type, deleted_elements } = deleteOperation;
  const deletedElementsIds = deleted_elements.map((deleted) => deleted.id);
  const deletedElements = await elFindByIds(context, user, deletedElementsIds, { indices: [INDEX_DELETED_OBJECTS], withoutRels: false }) as BasicStoreObject[];
  const deletedRelationships = deletedElements.filter((e) => e.id !== main_entity_id) as BasicStoreRelation[];
  const mainElementToRestore = deletedElements.find((e) => e.id === main_entity_id);

  // check that we have main elements and all relationships in trash index
  if (!mainElementToRestore || deletedElements.length !== deleted_elements.length) {
    throw FunctionalError('Cannot restore from DeleteOperation: one or more deleted elements not found.', { id: deleteOperation.id });
  }

  // check that all relationships targets (from & to) exist, either in live DB or in elementsToRestore
  // Note this will include the main entity if it's a relationship
  const allRelationshipsToRestore = deletedElements.filter((e) => isStixRelationship(e.entity_type));
  const targetIdsToFind = new Set<string>(); // targets not found in elements to restore, we will search them in live DB.
  for (let i = 0; i < allRelationshipsToRestore.length; i += 1) {
    const { fromId, toId } = allRelationshipsToRestore[i] as BasicStoreRelation;
    if (!deletedElementsIds.includes(fromId)) {
      targetIdsToFind.add(fromId);
    }
    if (!deletedElementsIds.includes(toId)) {
      targetIdsToFind.add(toId);
    }
  }
  if (targetIdsToFind.size > 0) {
    const targets = await elFindByIds(context, user, [...targetIdsToFind], { baseData: true, baseFields: ['internal_id', 'entity_type'] }) as BasicStoreObject[];
    if (targets.length < targetIdsToFind.size) {
      // Some elements are missing, check if they are in the trash
      const availableIds = targets.map((t) => t.id);
      const missingIds = [...targetIdsToFind].filter((id) => !availableIds.includes(id));
      const targetsFromTrash = await elFindByIds(context, user, missingIds, { baseFields: ['internal_id', 'entity_type'], indices: READ_INDEX_DELETED_OBJECTS }) as BasicStoreObject[];
      if (targetsFromTrash.length > 0) {
        // only hint the first 3 ones
        let name = targetsFromTrash.slice(0, 3).map((t) => extractRepresentative(t).main).join(',');
        if (targetsFromTrash.length > 3) name = `${name}, ... and ${targetsFromTrash.length - 3} more`;
        throw FunctionalError(`Cannot restore: a relationship targets deleted elements [${name}], restore them before retrying`, { deleteOperationId: deleteOperation.id });
      }
      // in this last case, the DeleteOperation is actually irrecoverable
      throw FunctionalError('Cannot restore: a target element of a relationship has been permanently deleted and cannot be recovered', { deleteOperationId: deleteOperation.id });
    }
  }

  const mainElementToRestoreInput = convertStoreEntityToInput(mainElementToRestore);
  const mainElementType = mainElementToRestore.entity_type;
  if (isStixObject(mainElementType)) {
    const existingEntities = await getExistingEntities(context, user, mainElementToRestoreInput, mainElementType);
    if (existingEntities.length > 0) {
      throw FunctionalError('Cannot restore entity, duplicate existing entity detected', { deleteOperationId: deleteOperation.id });
    }
  } else if (isStixRelationship(mainElementType) || isStixSightingRelationship(mainElementType)) {
    const from = { internal_id: mainElementToRestoreInput.fromId };
    const to = { internal_id: mainElementToRestoreInput.toId };
    const relationshipInput = { ...mainElementToRestoreInput, from, to };
    const existingRelations = await getExistingRelations(context, user, relationshipInput);
    if (existingRelations.length > 0) {
      throw FunctionalError('Cannot restore relation, duplicate existing relation detected', { deleteOperationId: deleteOperation.id });
    }
  }

  // filter out the refs registered in the schema for the main entity (they are recreated already when restoring the main entity)
  const availableRefAttributesDatabaseNames = schemaRelationsRefDefinition.getRelationsRef(main_entity_type).map((attr) => attr.databaseName);

  const relationshipsToRestore = deletedRelationships.filter((r) => !availableRefAttributesDatabaseNames.includes(r.entity_type));

  const availableElementsIds = [
    main_entity_id, // already restored
    ...targetIdsToFind, // already in database
  ];
  let relationshipNotHandledYet = [...relationshipsToRestore];
  const relationShipHandled = [];
  while (relationShipHandled.length < relationshipsToRestore.length) {
    const currentSize = relationshipNotHandledYet.length;
    for (let i = 0; i < currentSize; i += 1) {
      const relationship = relationshipsToRestore[i];
      const { id: relId, fromId, toId } = relationship;
      // if both sides are in DB (previously or already restored), we can restore this relationship
      if (availableElementsIds.includes(fromId) && availableElementsIds.includes(toId)) {
        // note we handle also the refs relationship 'to' the main entity (like 'objects' for containers)
        if (isStixRelationship(relationship.entity_type)) { // ref, sighting and core
          availableElementsIds.push(relId); // now this one is available, in case we have relationships over relationships in the cluster
          relationShipHandled.push(relationship);
        } else {
          logApp.warn('Cannot restore relationship', { entity_type: relationship.entity_type });
        }
      }
    }
    // optimization: for next iteration, do not keep the elements already restored
    relationshipNotHandledYet = relationshipNotHandledYet.filter((r) => !availableElementsIds.includes(r.id));
    // failsafe
    if (currentSize === relationshipNotHandledYet.length && currentSize > 0) {
      // nothing has been handled on this iteration and we are stuck in a loop
      throw FunctionalError('Cannot restore the cluster, cycle detected');
    }
  }

  return {
    mainElementToRestore,
    mainElementToRestoreInput,
    orderedRelationshipsToRestore: relationShipHandled,
  };

  // -> filter out only relationships, not refs (handled below directly)
  // -> all relationships point to existing elements (or the ones in the cluster)
  // -> if a relationship points to something missing in Db, but present in the trash, throw explicit error message to indicate
  //    which one (id+representative+entity_type, so frontend can display something useful)
};

//----------------------------------------------------------------------------------------------------------------------

export const findById = async (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityDeleteOperation>(context, user, id, ENTITY_TYPE_DELETE_OPERATION);
};

export const findDeleteOperationPaginated = async (context: AuthContext, user: AuthUser, args: QueryDeleteOperationsArgs) => {
  return pageEntitiesConnection<BasicStoreEntityDeleteOperation>(context, user, [ENTITY_TYPE_DELETE_OPERATION], args);
};

export const findOldDeleteOperations = (context: AuthContext, user: AuthUser, daysOld: number, maxSize: number) => {
  const dateThreshold = new Date();
  dateThreshold.setDate(dateThreshold.getDate() - daysOld);
  const filters = {
    orderBy: 'created_at',
    orderMode: OrderingMode.Asc,
    mode: FilterMode.And,
    filters: [
      { key: ['created_at'], values: [prepareDate(dateThreshold)], operator: FilterOperator.Lt }
    ],
    filterGroups: [],
  };
  const args = {
    filters,
    maxSize,
  };
  return fullEntitiesList<BasicStoreEntityDeleteOperation>(context, user, [ENTITY_TYPE_DELETE_OPERATION], args);
};

/**
 * Permanently delete a given DeleteOperation and all the elements referenced in it, wherever they are (restored or not).
 */
export const processDeleteOperation = async (context: AuthContext, user: AuthUser, id: string, opts: ConfirmDeleteOptions = {}) => {
  const { isRestoring } = opts;
  const deleteOperation = await findById(context, user, id);
  if (!deleteOperation) {
    throw FunctionalError(`Delete operation ${id} cannot be found`);
  }
  controlUserConfidenceAgainstElement(user, deleteOperation);
  controlUserRestrictDeleteAgainstElement(user, deleteOperation);

  const { main_entity_id, deleted_elements } = deleteOperation;
  // get all deleted elements & main deleted entity (from deleted_objects index)
  const mainEntityId = main_entity_id;
  const deletedElementsIds = deleted_elements.map((el) => el.id);
  const deletedElements: any[] = await elFindByIds(context, user, deletedElementsIds, { indices: READ_INDEX_DELETED_OBJECTS }) as any[];
  const mainDeletedEntity = deletedElements.find((el) => el.internal_id === mainEntityId);
  if (mainDeletedEntity && isStixObject(mainDeletedEntity.entity_type)) {
    if (isRestoring) {
      // cluster restored: flag the files available for search again
      await elUpdateRemovedFiles(mainDeletedEntity, false);
    } else {
      // confirm delete: delete associated files permanently
      await deleteAllObjectFiles(context, user, mainDeletedEntity);
    }
  }
  // delete elements
  await elDeleteInstances([...deletedElements]);
  // finally delete deleteOperation
  await elDeleteElements(context, user, [deleteOperation]);
  return id;
};

export const confirmDelete = async (context: AuthContext, user: AuthUser, id: string) => {
  // lock the delete operation
  let lock;
  try {
    lock = await lockResources([id]);
    return await processDeleteOperation(context, user, id, { isRestoring: false });
  } catch (e: any) {
    if (e.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds: [id] });
    }
    throw e;
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};

export const restoreDelete = async (context: AuthContext, user: AuthUser, id: string) => {
  const deleteOperation = await findById(context, user, id);
  if (!deleteOperation) {
    throw FunctionalError('Cannot find DeleteOperation', { id });
  }
  const { main_entity_id, main_entity_type } = deleteOperation;

  if (!isStixObject(main_entity_type) && !isStixRelationship(main_entity_type)) {
    throw FunctionalError('Cannot restore main entity: unhandled entity type', { main_entity_type });
  }

  // check that the element cluster can be fully restored, throw error otherwise
  const { mainElementToRestore, mainElementToRestoreInput, orderedRelationshipsToRestore } = await resolveEntitiesToRestore(context, user, deleteOperation);

  // check confidence of main element to restore
  controlUserConfidenceAgainstElement(user, mainElementToRestore);

  // lock the delete operation
  let lock;
  try {
    lock = await lockResources([id]);

    // restore main element
    let result: any;
    if (isStixObject(mainElementToRestore.entity_type)) {
      result = await createEntity(context, user, mainElementToRestoreInput, main_entity_type, { restore: true });
    } else if (isStixRelationship(mainElementToRestore.entity_type)) {
      result = await createRelation(context, user, mainElementToRestoreInput, { restore: true });
    }

    const upsertedElements: Record<string, string> = {};
    const mainEntityRestoredId = result.id;
    if (mainEntityRestoredId !== main_entity_id) {
      upsertedElements[main_entity_id] = mainEntityRestoredId;
      logApp.info('Main entity has been restored with with different id (upsert)');
    }

    // restore the relationships
    for (let i = 0; i < orderedRelationshipsToRestore.length; i += 1) {
      const relationToRestore = orderedRelationshipsToRestore[i] as BasicStoreRelation;
      const isInferredRelation = Object.keys(relationToRestore).some((k) => k.startsWith(RULE_PREFIX));
      const relationshipInput = convertStoreEntityToInput(relationToRestore, upsertedElements);
      if (!isInferredRelation) result = await createRelation(context, user, relationshipInput); // created with same id as part of relationshipInput
      else {
        const rule = Object.keys(relationToRestore).find((k) => k.startsWith(RULE_PREFIX));
        if (rule === undefined) {
          logApp.warn('Inferred rule could not be found', { relation: relationToRestore });
        } else {
          const ruleID = rule.substring(RULE_PREFIX.length);
          const ruleValues = (relationToRestore as Record<string, any>)[rule][0];
          const ruleContent = createRuleContent(ruleID, ruleValues.dependencies, ruleValues.explanation, ruleValues.data);
          result = await createInferredRelation(context, relationshipInput, ruleContent);
        }
      }
      if (result.id && result.id !== relationshipInput.id) {
        upsertedElements[relationshipInput.id] = result.id;
        logApp.info('Relationship has been restored with different id (upsert)', { upsertId: result.id, originalId: relationshipInput.id });
      }
      if (result.element && result.element.id && result.element.id !== relationshipInput.id) {
        upsertedElements[relationshipInput.id] = result.element.id;
        logApp.info('Relationship has been restored with different id (upsert)', { upsertId: result.element.id, originalId: relationshipInput.id });
      }
    }

    // now delete the DeleteOperation and all the elements in the trash index
    await processDeleteOperation(context, user, id, { isRestoring: true });

    return mainEntityRestoredId;
  } catch (e: any) {
    if (e.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds: [id] });
    }
    throw e;
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};
