import { assoc, filter, map, propOr, isNil, flatten, concat, pluck, uniq, includes } from 'ramda';
import {
  createRelation,
  createRelations,
  deleteEntityById,
  deleteRelationsByFromAndTo,
  escapeString,
  internalLoadById,
  listEntities,
  listFromEntitiesThroughRelation,
  listToEntitiesThroughRelation,
  load,
  loadById,
  updateAttribute,
} from '../database/grakn';
import {
  addStixCoreRelationship,
  findAll as findAllStixRelations,
  findAll as relationFindAll,
} from './stixCoreRelationship';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { FunctionalError } from '../config/errors';
import { isStixCoreObject } from '../schema/stixCoreObject';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_META_RELATIONSHIP, ENTITY_TYPE_IDENTITY } from '../schema/general';
import {
  isStixMetaRelationship,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixMetaRelationship';
import {
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  resolveAliasesField,
} from '../schema/stixDomainObject';
import {
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_MARKING_DEFINITION,
} from '../schema/stixMetaObject';
import { isStixRelationship } from '../schema/stixRelationship';
import { reportContainsStixObjectOrStixRelationship } from './report';
import { noteContainsStixObjectOrStixRelationship } from './note';
import { opinionContainsStixObjectOrStixRelationship } from './opinion';

export const findAll = async (args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = filter((type) => isStixCoreObject(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CORE_OBJECT);
  }
  return listEntities(types, ['standard_id'], args);
};

export const findById = async (stixCoreObjectId) => loadById(stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);

export const createdBy = async (stixCoreObjectId) => {
  const element = await load(
    `match $to isa ${ENTITY_TYPE_IDENTITY};
    $rel(${RELATION_CREATED_BY}_from:$from, ${RELATION_CREATED_BY}_to: $to) isa ${RELATION_CREATED_BY};
    $from has internal_id "${escapeString(stixCoreObjectId)}"; get;`,
    ['to']
  );
  return element && element.to;
};

export const reports = async (stixCoreObjectId) => {
  return listFromEntitiesThroughRelation(stixCoreObjectId, null, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_REPORT);
};

export const notes = (stixCoreObjectId) => {
  return listFromEntitiesThroughRelation(stixCoreObjectId, null, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_NOTE);
};

export const opinions = (stixCoreObjectId) => {
  return listFromEntitiesThroughRelation(stixCoreObjectId, null, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_OPINION);
};

export const labels = async (stixCoreObjectId) => {
  return listToEntitiesThroughRelation(stixCoreObjectId, null, RELATION_OBJECT_LABEL, ENTITY_TYPE_LABEL);
};

export const markingDefinitions = (stixCoreObjectId) => {
  return listToEntitiesThroughRelation(stixCoreObjectId, null, RELATION_OBJECT_MARKING, ENTITY_TYPE_MARKING_DEFINITION);
};

export const killChainPhases = (stixDomainObjectId) => {
  return listToEntitiesThroughRelation(
    stixDomainObjectId,
    null,
    RELATION_KILL_CHAIN_PHASE,
    ENTITY_TYPE_KILL_CHAIN_PHASE
  );
};

export const externalReferences = (stixDomainObjectId) => {
  return listToEntitiesThroughRelation(
    stixDomainObjectId,
    null,
    RELATION_EXTERNAL_REFERENCE,
    ENTITY_TYPE_EXTERNAL_REFERENCE
  );
};

export const stixCoreRelationships = (stixCoreObjectId, args) => {
  const finalArgs = assoc('fromId', stixCoreObjectId, args);
  return relationFindAll(finalArgs);
};

export const stixCoreObjectAddRelation = async (user, stixCoreObjectId, input) => {
  const data = await internalLoadById(stixCoreObjectId);
  if (!isStixCoreObject(data.entity_type) || !isStixRelationship(input.relationship_type)) {
    throw FunctionalError('Only stix-meta-relationship can be added through this method.', { stixCoreObjectId, input });
  }
  const finalInput = assoc('fromId', stixCoreObjectId, input);
  return createRelation(user, finalInput);
};

export const stixCoreObjectAddRelations = async (user, stixCoreObjectId, input) => {
  const stixCoreObject = await loadById(stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  if (!stixCoreObject) {
    throw FunctionalError('Cannot add the relation, Stix-Core-Object cannot be found.');
  }
  if (!isStixMetaRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = map(
    (n) => ({ fromId: stixCoreObjectId, toId: n, relationship_type: input.relationship_type }),
    input.toIds
  );
  await createRelations(user, finalInput);
  return loadById(stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT).then((entity) =>
    notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, entity, user)
  );
};

export const stixCoreObjectDeleteRelation = async (user, stixCoreObjectId, toId, relationshipType) => {
  const stixCoreObject = await loadById(stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  if (!stixCoreObject) {
    throw FunctionalError('Cannot delete the relation, Stix-Core-Object cannot be found.');
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(user, stixCoreObjectId, toId, relationshipType, ABSTRACT_STIX_META_RELATIONSHIP);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, stixCoreObject, user);
};

export const stixCoreObjectEditField = async (user, stixCoreObjectId, input) => {
  const stixCoreObject = await loadById(stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  if (!stixCoreObject) {
    throw FunctionalError('Cannot edit the field, Stix-Core-Object cannot be found.');
  }
  const updatedStixCoreObject = await updateAttribute(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT, input);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, updatedStixCoreObject, user);
};

export const stixCoreObjectDelete = async (user, stixCoreObjectId) => {
  const stixCoreObject = await loadById(stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  if (!stixCoreObject) {
    throw FunctionalError('Cannot delete the object, Stix-Core-Object cannot be found.');
  }
  return deleteEntityById(user, stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
};

export const stixCoreObjectsDelete = async (user, stixCoreObjectsIds) => {
  // Relations cannot be created in parallel.
  for (let i = 0; i < stixCoreObjectsIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    await stixCoreObjectDelete(user, stixCoreObjectsIds[i]);
  }
  return stixCoreObjectsIds;
};

export const stixCoreObjectMerge = async (user, stixCoreObjectId, stixCoreObjectsIds, fieldsToCopy = []) => {
  // Pre-checks
  if (includes(stixCoreObjectId, stixCoreObjectsIds)) {
    throw FunctionalError(`Cannot merge entities, same ID detected in source and destination`, {
      stixCoreObjectId,
      stixCoreObjectsIds,
    });
  }
  // 0. Get the object
  const stixCoreObject = await loadById(stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);
  if (!stixCoreObject) {
    throw FunctionalError('Cannot merge the other objects, Stix-Object cannot be found.');
  }
  // 1. Update aliases & STIX IDs
  const stixCoreObjectsToBeMerged = await Promise.all(
    stixCoreObjectsIds.map(async (id) => loadById(id, ABSTRACT_STIX_CORE_OBJECT))
  );
  // 1.1 Update STIX IDs
  const stixIdsToAdd = flatten(pluck('x_opencti_stix_ids', stixCoreObjectsToBeMerged));
  const newStixIds = uniq(concat(stixCoreObject.x_opencti_stix_ids, stixIdsToAdd));
  await stixCoreObjectEditField(user, stixCoreObjectId, {
    key: 'x_opencti_stix_ids',
    value: newStixIds,
  });
  // 1.2 Update the alias field
  const aliasField = resolveAliasesField(stixCoreObject.entity_type);
  if (!isNil(stixCoreObject[aliasField])) {
    const aliasesToAdd = flatten(pluck(aliasField, stixCoreObjectsToBeMerged));
    const newAliases = uniq(concat(stixCoreObject[aliasField], aliasesToAdd));
    await stixCoreObjectEditField(user, stixCoreObjectId, {
      key: aliasField,
      value: newAliases,
    });
  }
  // eslint-disable-next-line no-restricted-syntax
  for (const field of fieldsToCopy) {
    const values = flatten(pluck(field, stixCoreObjectsToBeMerged));
    if (values.length > 0 && values[0].length > 0) {
      // eslint-disable-next-line no-await-in-loop
      await stixCoreObjectEditField(user, stixCoreObjectId, {
        key: field,
        value: values[0],
      });
    }
  }
  // 2. Copy the relationships
  await Promise.all(
    stixCoreObjectsIds.map(async (id) => {
      const relations = await findAllStixRelations({ fromId: id });
      return Promise.all(
        relations.edges.map(async (relationEdge) => {
          const relation = relationEdge.node;
          const relationCreatedBy = await createdBy(relation.id);
          const relationMarkingDefinitions = await markingDefinitions(relation.id);
          const relationkillChainPhases = await killChainPhases(relation.id);
          const relationReports = await reports(relation.id);
          const relationNotes = await notes(relation.id);
          const relationOpinions = await opinions(relation.id);
          const relationToCreate = {
            fromId: relation.fromId === id ? stixCoreObjectId : relation.fromId,
            toId: relation.toId === id ? stixCoreObjectId : relation.toId,
            relationship_type: relation.entity_type,
            confidence: relation.confidence,
            description: relation.description,
            start_time: relation.start_time,
            stop_time: relation.stop_time,
            created: relation.created,
            modified: relation.modified,
            createdBy: propOr(null, 'id', relationCreatedBy),
            objectMarking: map((n) => n.node.id, relationMarkingDefinitions.edges),
            killChainPhases: map((n) => n.node.id, relationkillChainPhases.edges),
          };
          const newRelation = await addStixCoreRelationship(user, relationToCreate);
          await Promise.all(
            relationReports.edges.map((report) => {
              return stixCoreObjectAddRelation(user, report.node.id, {
                toId: newRelation.internal_id,
                relationship_type: RELATION_OBJECT,
              });
            })
          );
          await Promise.all(
            relationNotes.edges.map((note) => {
              return stixCoreObjectAddRelation(user, note.node.id, {
                toId: newRelation.internal_id,
                relationship_type: RELATION_OBJECT,
              });
            })
          );
          await Promise.all(
            relationOpinions.edges.map((opinion) => {
              return stixCoreObjectAddRelation(user, opinion.node.id, {
                toId: newRelation.internal_id,
                relationship_type: RELATION_OBJECT,
              });
            })
          );
          return true;
        })
      );
    })
  );
  // 3. Copy reports refs
  await Promise.all(
    stixCoreObjectsIds.map(async (id) => {
      const stixCoreObjectReports = await reports(id);
      return Promise.all(
        stixCoreObjectReports.edges.map(async (reportEdge) => {
          const report = reportEdge.node;
          const alreadyInReport = await reportContainsStixObjectOrStixRelationship(report.id, stixCoreObjectId);
          if (!alreadyInReport) {
            return stixCoreObjectAddRelation(user, report.id, {
              toId: stixCoreObjectId,
              relationship_type: RELATION_OBJECT,
            });
          }
          return true;
        })
      );
    })
  );
  // 4. Copy notes refs
  await Promise.all(
    stixCoreObjectsIds.map(async (id) => {
      const stixCoreObjectNotes = await notes(id);
      return Promise.all(
        stixCoreObjectNotes.edges.map(async (noteEdge) => {
          const note = noteEdge.node;
          const alreadyInNote = await noteContainsStixObjectOrStixRelationship(note.id, stixCoreObjectId);
          if (!alreadyInNote) {
            return stixCoreObjectAddRelation(user, note.id, {
              toId: stixCoreObjectId,
              relationship_type: RELATION_OBJECT,
            });
          }
          return true;
        })
      );
    })
  );
  // 5. Copy opinions refs
  await Promise.all(
    stixCoreObjectsIds.map(async (id) => {
      const stixCoreObjectOpinions = await opinions(id);
      return Promise.all(
        stixCoreObjectOpinions.edges.map(async (opinionEdge) => {
          const opinion = opinionEdge.node;
          const alreadyInOpinion = await opinionContainsStixObjectOrStixRelationship(opinion.id, stixCoreObjectId);
          if (!alreadyInOpinion) {
            return stixCoreObjectAddRelation(user, opinion.id, {
              toId: stixCoreObjectId,
              relationship_type: RELATION_OBJECT,
            });
          }
          return true;
        })
      );
    })
  );
  // 8. Delete entities
  await stixCoreObjectsDelete(user, stixCoreObjectsIds);
  // 9. Return entity
  return loadById(stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT).then((finalStixCoreObject) =>
    notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, finalStixCoreObject, user)
  );
};
// endregion
