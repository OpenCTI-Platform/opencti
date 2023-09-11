import { listAllEntities, listAllRelations } from '../database/middleware-loader';
import { executionContext, SYSTEM_USER, TAXIIAPI_SETCOLLECTIONS } from '../utils/access';
import { RELATION_ACCESSES_TO, RELATION_HAS_CAPABILITY } from '../schema/internalRelationship';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_STREAM_COLLECTION } from '../schema/internalObject';
import { elDeleteElements, elLoadById, elReplace } from '../database/engine';
import { createRelationRaw, storeLoadByIdWithRefs } from '../database/middleware';

export const up = async (next) => {
  // 01. Stream accesses-to migration to use authorized_members and authorized_authorities
  const context = executionContext('migration');
  const streams = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_STREAM_COLLECTION]);
  for (let index = 0; index < streams.length; index += 1) {
    const stream = streams[index];
    const args = { toId: stream.internal_id, fromTypes: [ENTITY_TYPE_GROUP], toTypes: [ENTITY_TYPE_STREAM_COLLECTION] };
    const relations = await listAllRelations(context, SYSTEM_USER, RELATION_ACCESSES_TO, args);
    if (relations.length > 0) {
      const authorized_members = relations.map((r) => ({ id: r.fromId, access_right: 'view' }));
      const patch = { authorized_members, authorized_authorities: [TAXIIAPI_SETCOLLECTIONS] };
      await elReplace(stream._index, stream.internal_id, { doc: patch });
      await elDeleteElements(context, SYSTEM_USER, relations, storeLoadByIdWithRefs);
    }
  }
  // 02. Migrate capability STREAMAPI to TAXIIAPI
  // ------ Access data sharing
  const accessTaxii = await elLoadById(context, SYSTEM_USER, 'capability--d258afde-7a8a-5917-8b4b-83119d3f8e52');
  const accessPatch = { description: 'Access data sharing' };
  await elReplace(accessTaxii._index, accessTaxii.internal_id, { doc: accessPatch });
  // ------ Manage data sharing
  const manageTaxii = await elLoadById(context, SYSTEM_USER, 'capability--24f9401c-8a77-59d5-8a8f-4ea21a1a733b');
  const managePatch = { description: 'Manage data sharing' };
  await elReplace(manageTaxii._index, manageTaxii.internal_id, { doc: managePatch });
  // ------ Roles that contains STREAMAPI must now contain TAXIIAPI
  const streamApi = await elLoadById(context, SYSTEM_USER, 'capability--beaa8173-6da3-5930-a0df-00e8feac9d52');
  const capabilityRelations = await listAllRelations(context, SYSTEM_USER, RELATION_HAS_CAPABILITY, { toId: streamApi.internal_id });
  for (let capaIndex = 0; capaIndex < capabilityRelations.length; capaIndex += 1) {
    const capabilityRelation = capabilityRelations[capaIndex];
    await createRelationRaw(context, SYSTEM_USER, { fromId: capabilityRelation.fromId, relationship_type: RELATION_HAS_CAPABILITY, toId: accessTaxii.internal_id });
  }
  // ------ Deletes STREAMAPI capability
  await elDeleteElements(context, SYSTEM_USER, [streamApi, ...capabilityRelations]);
  next();
};

export const down = async (next) => {
  next();
};
