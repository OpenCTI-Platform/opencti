import { executionContext, SYSTEM_USER } from '../utils/access';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../modules/threatActorIndividual/threatActorIndividual-types';
import { elCount, elRawUpdateByQuery } from '../database/engine';
import {
  READ_ENTITIES_INDICES,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_META_OBJECTS,
  READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED
} from '../database/utils';
import { DatabaseError } from '../config/errors';
import { ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../schema/stixDomainObject';
import { elList, listAllEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_THREAT_ACTOR } from '../schema/general';
import { builtInOv, openVocabularies } from '../modules/vocabulary/vocabulary-utils';
import { ENTITY_TYPE_VOCABULARY } from '../modules/vocabulary/vocabulary-types';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { logApp } from '../config/conf';

const message = '[MIGRATION] Threat-actors to group and individual';

const updateOVCategory = async (fromOV, toOV) => {
  const updateIndividualQuery = {
    script: {
      params: { toOV },
      source: 'ctx._source.category = params.toOV;',
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'Vocabulary' } } },
          { term: { 'category.keyword': { value: fromOV } } },
        ],
      },
    },
  };
  await elRawUpdateByQuery({
    index: [READ_INDEX_STIX_META_OBJECTS],
    refresh: true,
    wait_for_completion: true,
    body: updateIndividualQuery
  }).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
};

const createIndividualThreatCategories = async (context) => {
  const categories = [
    { individual: 'threat_actor_individual_type_ov', group: 'threat_actor_group_type_ov' },
    { individual: 'threat_actor_individual_role_ov', group: 'threat_actor_group_role_ov' },
    { individual: 'threat_actor_individual_sophistication_ov', group: 'threat_actor_group_sophistication_ov' }
  ];
  for (let indexCategory = 0; indexCategory < categories.length; indexCategory += 1) {
    const { individual, group } = categories[indexCategory];
    const vocabularies = openVocabularies[individual] ?? [];
    const individualVocabKeys = vocabularies.map((v) => v.key);
    const args = { connectionFormat: false, filters: [{ key: 'category', values: [group] }] };
    const vocabsFromGroup = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_VOCABULARY], args);
    const groupExistingVocabs = (vocabsFromGroup ?? []).map((v) => ({ key: v.name, description: v.description, aliases: v.aliases }));
    const groupVocabToMaintains = groupExistingVocabs.filter((g) => !individualVocabKeys.includes(g.key));
    logApp.info(`${message} > Create ${groupVocabToMaintains.length} vocabularies for category ${individual}`);
    vocabularies.push(...groupVocabToMaintains);
    for (let i = 0; i < vocabularies.length; i += 1) {
      const { key, description, aliases } = vocabularies[i];
      const data = {
        name: key,
        description: description ?? '',
        aliases: aliases ?? [],
        category: individual,
        builtIn: builtInOv.includes(individual)
      };
      await addVocabulary(context, SYSTEM_USER, data);
    }
  }
};

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');
  // Rename threat actor ov to group
  logApp.info(`${message} > Migration open vocabularies`);
  await updateOVCategory('threat_actor_type_ov', 'threat_actor_group_type_ov');
  await updateOVCategory('threat_actor_role_ov', 'threat_actor_group_role_ov');
  await updateOVCategory('threat_actor_sophistication_ov', 'threat_actor_group_sophistication_ov');
  // Create new ov from individual
  await createIndividualThreatCategories(context);
  // Iterator over all threat actors
  // Some must be converted to group and some to individual
  const filters = [{ key: 'entity_type', values: [ENTITY_TYPE_THREAT_ACTOR] }];
  const threatCount = await elCount(context, SYSTEM_USER, READ_ENTITIES_INDICES, { filters });
  logApp.info(`${message} > Migrating threat actors 0/${threatCount}`);
  let processNumber = 0;
  const callback = async (threatActors) => {
    processNumber += threatActors.length;
    for (let index = 0; index < threatActors.length; index += 1) {
      const threatActor = threatActors[index];
      const isIndividualTarget = threatActor.resource_level === 'individual';
      const toType = isIndividualTarget ? ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL : ENTITY_TYPE_THREAT_ACTOR_GROUP;
      const standardId = generateStandardId(toType, threatActor);
      // Update the entity
      const updateEntityQuery = {
        script: {
          params: { toType, standardId },
          source: 'ctx._source.entity_type = params.toType; ctx._source.standard_id = params.standardId;',
        },
        query: {
          term: { 'internal_id.keyword': { value: threatActor.internal_id } }
        },
      };
      const entityPromise = elRawUpdateByQuery({
        index: [READ_INDEX_STIX_DOMAIN_OBJECTS],
        refresh: true,
        wait_for_completion: true,
        body: updateEntityQuery
      }).catch((err) => {
        throw DatabaseError('Error updating elastic', { error: err });
      });
      // update the relations
      const updateRelationsQuery = {
        script: {
          params: { toType, toId: threatActor.internal_id },
          source: 'for(def connection : ctx._source.connections) {'
              + 'if (connection.internal_id == params.toId) { connection.types.add(params.toType); } '
              + '} '
              + 'if (ctx._source.fromId == params.toId) { ctx._source.fromType = params.toType; }'
              + 'if (ctx._source.toId == params.toId) { ctx._source.toType = params.toType; }'
        },
        query: {
          bool: {
            should: [
              { term: { 'fromId.keyword': { value: threatActor.internal_id } } },
              { term: { 'toId.keyword': { value: threatActor.internal_id } } }
            ],
          }
        },
      };
      const relationsPromise = elRawUpdateByQuery({
        index: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
        refresh: true,
        wait_for_completion: true,
        body: updateRelationsQuery
      }).catch((err) => {
        throw DatabaseError('Error updating elastic', { error: err });
      });
      await Promise.all([entityPromise, relationsPromise]);
    }
    logApp.info(`${message} > Migrating threat actors ${processNumber}/${threatCount}`);
  };
  await elList(context, SYSTEM_USER, [READ_INDEX_STIX_DOMAIN_OBJECTS], { filters, callback });
  // Done with the migration
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
