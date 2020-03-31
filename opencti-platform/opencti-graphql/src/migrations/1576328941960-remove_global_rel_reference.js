import { el } from '../database/elasticSearch';
import { INDEX_STIX_ENTITIES } from '../database/utils';

const removeAttributeForEntityType = async (entityType, role) => {
  await el.updateByQuery({
    index: INDEX_STIX_ENTITIES,
    body: {
      script: {
        source: `if (ctx._source['rel_${role}.internal_id_key'] != null) ctx._source.remove('rel_${role}.internal_id_key')`,
      },
      query: {
        bool: {
          must: { match_phrase: { entity_type: entityType } },
        },
      },
    },
  });
};

export const up = async (next) => {
  await removeAttributeForEntityType('tag', 'tagged');
  await removeAttributeForEntityType('kill-chain-phase', 'kill_chain_phases');
  await removeAttributeForEntityType('marking-definition', 'object_marking_refs');
  await removeAttributeForEntityType('organization', 'created_by_ref');
  next();
};

export const down = async (next) => {
  next();
};
