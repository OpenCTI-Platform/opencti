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
import { listAllEntities } from '../database/middleware-loader';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';

async function fetchPersistedInvestigations() {
  return await listAllEntities(
    executionContext('migration'),
    SYSTEM_USER,
    [ENTITY_TYPE_WORKSPACE],
    { type: 'investigation' }
  );
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
        source: ''
          + 'for (def investigationId : params.investigationIds) {'
          + '  if (ctx._source[params.field].contains(investigationId)) {'
          + '    ctx._source[params.field].remove(ctx._source[params.field].indexOf(investigationId)) '
          + '  }'
          + '}',
        params: {
          field: 'rel_has-reference.internal_id',
          investigationIds
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
        term: {
          fromType: {
            value: 'Workspace'
          }
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
        match: { type: 'investigation' }
      }
    }
  );
}

export const up = async (next) => {
  const investigationIds = (await fetchPersistedInvestigations()).map((investigation) => investigation.id);

  await removeInvestigationsReferencesFromInvestigatedEntities(investigationIds);
  await deleteInvestigationsInternalRelations();
  await updateInvestigationsField('rel_has-reference.internal_id', 'investigated_entities_ids');

  next();
};

export const down = async (next) => {
  next();
};
