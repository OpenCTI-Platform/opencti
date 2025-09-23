import { elDeleteByQueryForMigration, elUpdateByQueryForMigration } from '../database/engine';
import {
  READ_INDEX_INTERNAL_OBJECTS,
  READ_INDEX_INTERNAL_RELATIONSHIPS,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_META_OBJECTS,
  READ_INDEX_STIX_META_RELATIONSHIPS
} from '../database/utils';
import { fullEntitiesList } from '../database/middleware-loader';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';

async function fetchPersistedInvestigations() {
  const context = executionContext('migration');
  return await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_WORKSPACE], { type: 'investigation' });
}

async function removeInvestigationsReferencesFromInvestigatedEntities(investigationIds) {
  await elUpdateByQueryForMigration(
    '[MIGRATION] removing investigations references from investigated entities',
    [
      READ_INDEX_STIX_CORE_RELATIONSHIPS,
      READ_INDEX_STIX_META_RELATIONSHIPS,
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      READ_INDEX_STIX_CYBER_OBSERVABLES,
      READ_INDEX_STIX_META_OBJECTS,
    ],
    {
      script: {
        source: 'ctx._source.remove(params.field)',
        params: {
          field: 'rel_has-reference.internal_id'
        }
      },
      query: {
        terms: { 'rel_has-reference.internal_id.keyword': investigationIds }
      }
    }
  );
}

async function deleteInvestigationsInternalRelations() {
  await elDeleteByQueryForMigration(
    '[MIGRATION] delete investigations internal relations',
    [READ_INDEX_INTERNAL_RELATIONSHIPS],
    {
      query: {
        bool: {
          must: [
            { term: { 'fromType.keyword': { value: 'Workspace' } } },
            { term: { 'relationship_type.keyword': { value: 'has-reference' } } }
          ]
        }
      }
    }
  );
}

async function updateInvestigationsField(oldField, newField) {
  await elUpdateByQueryForMigration(
    `[MIGRATION] update investigation field '${oldField}' to '${newField}'`,
    [READ_INDEX_INTERNAL_OBJECTS],
    {
      script: {
        source: ''
          + 'ctx._source[params.newField] = ctx._source[params.oldField];'
          + 'ctx._source.remove(params.oldField)',
        params: { oldField, newField }
      },
      query: {
        bool: {
          must: [
            { term: { 'entity_type.keyword': { value: 'Workspace' } } },
            { term: { 'type.keyword': { value: 'investigation' } } }
          ]
        }
      }
    }
  );
}

export const up = async (next) => {
  const investigations = await fetchPersistedInvestigations();
  const investigationIds = investigations.map((investigation) => investigation.id);
  await removeInvestigationsReferencesFromInvestigatedEntities(investigationIds);
  await deleteInvestigationsInternalRelations();
  await updateInvestigationsField('rel_has-reference.internal_id', 'investigated_entities_ids');
  next();
};

export const down = async (next) => {
  next();
};
