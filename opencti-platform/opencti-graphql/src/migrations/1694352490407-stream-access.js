import { listAllEntities, listAllRelations } from '../database/middleware-loader';
import { executionContext, SYSTEM_USER, TAXIIAPI_SETCOLLECTIONS } from '../utils/access';
import { RELATION_ACCESSES_TO } from '../schema/internalRelationship';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_STREAM_COLLECTION } from '../schema/internalObject';
import { elDeleteElements, elReplace, } from '../database/engine';
import { storeLoadByIdWithRefs } from '../database/middleware';

export const up = async (next) => {
  // Stream accesses-to migration to use authorized_members and authorized_authorities
  const context = executionContext('migration');
  const streams = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_STREAM_COLLECTION]);
  for (let index = 0; index < streams.length; index += 1) {
    const stream = streams[index];
    const args = { toId: stream.internal_id, fromTypes: [ENTITY_TYPE_GROUP], toTypes: [ENTITY_TYPE_STREAM_COLLECTION] };
    const relations = await listAllRelations(context, SYSTEM_USER, RELATION_ACCESSES_TO, args);
    const authorized_members = relations.map((r) => ({
      id: r.fromId,
      access_right: 'view',
    }));
    const patch = { authorized_members, authorized_authorities: [TAXIIAPI_SETCOLLECTIONS] };
    await elReplace(stream._index, stream.internal_id, { doc: patch });
    await elDeleteElements(context, SYSTEM_USER, relations, storeLoadByIdWithRefs);
  }
  // Migrate capability STREAMAPI to TAXIIAPI
  // TODO
  //   name: TAXIIAPI,
  //   attribute_order: 2500,
  //   description: 'Access Taxii feed',
  //   dependencies: [{ name: 'SETCOLLECTIONS', description: 'Manage Taxii collections', attribute_order: 2510 }],
  // Access data sharing
  // Manage data sharing
  next();
};

export const down = async (next) => {
  next();
};
