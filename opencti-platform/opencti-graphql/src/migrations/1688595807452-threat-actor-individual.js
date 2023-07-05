import { elRawUpdateByQuery, elUpdateByQueryForMigration } from '../database/engine';
import {
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_META_OBJECTS,
  READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED
} from '../database/utils';
import { DatabaseError } from '../config/errors';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { builtInOv, openVocabularies } from '../modules/vocabulary/vocabulary-utils';
import { elList, listAllEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_VOCABULARY } from '../modules/vocabulary/vocabulary-types';
import { ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../schema/stixDomainObject';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../modules/threatActorIndividual/threatActorIndividual-types';

const convertIndividualResourceThreatActorToIndividualActor = async () => {
  const message = '[MIGRATION] Rewriting resource_level individual Threat-Actor-Group to Threat-Actor-Individual';
  const context = executionContext('migration');
  const callback = (threatActors) => threatActors.map(async (threatActor) => {
    const standardId = generateStandardId(ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL, threatActor);
    // region We need to update the entity for type and standard id
    const updateEntityQuery = {
      script: {
        params: { toType: 'Threat-Actor-Individual', standardId },
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
    // endregion
    // region We need to update all relations that from or to this id
    const updateRelationsQuery = {
      script: {
        params: { toType: 'Threat-Actor-Individual' },
        source: 'for(def connection : ctx._source.connections) {'
            + 'if (connection.types.contains("Threat-Actor-Group")) { '
            + 'connection.types.remove("Threat-Actor-Group");'
            + 'connection.types.add(params.toType);'
            + '} } '
            + 'ctx._source.fromType = params.toType;'
            + 'ctx._source.toType = params.toType;'
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
    const relationsPromise = elUpdateByQueryForMigration(message, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, updateRelationsQuery).catch((err) => {
      throw DatabaseError('Error updating elastic', { error: err });
    });
    // endregion
    return Promise.all([entityPromise, relationsPromise]);
  });
  const filters = [{ key: 'resource_level', values: ['individual'] }];
  const opts = { types: [ENTITY_TYPE_THREAT_ACTOR_GROUP], filters, callback };
  await elList(context, SYSTEM_USER, [READ_INDEX_STIX_DOMAIN_OBJECTS], opts);
};

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
        minimum_should_match: 1
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

const createIndividualThreatCategories = async () => {
  const context = executionContext('migration');
  const categories = [
    { individual: 'threat_actor_individual_role_ov', group: 'threat_actor_group_type_ov' },
    { individual: 'threat_actor_individual_type_ov', group: 'threat_actor_group_role_ov' },
    { individual: 'threat_actor_individual_sophistication_ov', group: 'threat_actor_group_sophistication_ov' }
  ];
  for (let indexCategory = 0; indexCategory < categories.length; indexCategory += 1) {
    const category = categories[indexCategory].individual;
    const vocabularies = openVocabularies[category] ?? [];
    const args = { connectionFormat: false, filters: [{ key: ['category'], values: [category.group] }] };
    const vocabsFromGroup = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_VOCABULARY], args);
    vocabularies.push(...(vocabsFromGroup ?? []));
    for (let i = 0; i < vocabularies.length; i += 1) {
      const { key, description, aliases } = vocabularies[i];
      const data = {
        name: key,
        description: description ?? '',
        aliases: aliases ?? [],
        category,
        builtIn: builtInOv.includes(category) };
      await addVocabulary(context, SYSTEM_USER, data);
    }
  }
};

export const up = async (next) => {
  // Migrate OV for threat actor group
  await updateOVCategory('threat_actor_type_ov', 'threat_actor_group_type_ov');
  await updateOVCategory('threat_actor_role_ov', 'threat_actor_group_role_ov');
  await updateOVCategory('threat_actor_sophistication_ov', 'threat_actor_group_sophistication_ov');
  // Create OV for threat actor individual
  await createIndividualThreatCategories();
  await convertIndividualResourceThreatActorToIndividualActor();
  next();
};

export const down = async (next) => {
  next();
};
