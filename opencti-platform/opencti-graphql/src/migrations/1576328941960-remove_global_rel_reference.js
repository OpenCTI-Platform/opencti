import { el, INDEX_STIX_ENTITIES } from '../database/elasticSearch';

const removeAttributeForEntityType = async (entityType, role) => {
  await el.updateByQuery({
    index: INDEX_STIX_ENTITIES,
    body: {
      script: {
        source: `if (ctx._source['rel_${role}.internal_id_key'] != null) ctx._source.remove('rel_${role}.internal_id_key')`
      },
      query: {
        bool: {
          must: { match_phrase: { entity_type: entityType } }
        }
      }
    }
  });
};

module.exports.up = async next => {
  await removeAttributeForEntityType('tag', 'tagged');
  await removeAttributeForEntityType('kill-chain-phase', 'kill_chain_phases');
  await removeAttributeForEntityType('marking-definition', 'object_marking_refs');
  await removeAttributeForEntityType('organization', 'created_by_ref');
  next();
};

module.exports.down = async next => {
  next();
};
