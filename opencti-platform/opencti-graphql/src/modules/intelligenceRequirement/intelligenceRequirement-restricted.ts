import type { AuthContext } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { internalLoadById } from '../../database/middleware-loader';
import { buildRestrictedEntity } from '../../database/middleware';
import { SYSTEM_USER } from '../../utils/access';

export const RESTRICTED_NAME = 'Restricted';

// The object as the reader of the request may see it (request batch loader when present, else a direct load)
const loadAsReader = async (context: AuthContext, id: string, type?: string | null) => {
  if (context.batch?.idsBatchLoader) return context.batch.idsBatchLoader.load({ id, type: type ?? undefined });
  if (!context.user) return null;
  return internalLoadById<BasicStoreEntity>(context, context.user, id, type ? { type } : undefined);
};

/**
 * An object a requirement points to (the entity of a match, a proof path anchor, relationship or container),
 * as the reader may see it: itself when readable, a Restricted placeholder when it exists but is hidden by
 * the reader's markings or organizations (the OpenCTI convention), null when it no longer exists.
 */
export const loadReadableOrRestricted = async (context: AuthContext, id: string | null | undefined, type?: string | null) => {
  if (!id) return null;
  const readable = await loadAsReader(context, id, type);
  if (readable) return readable;
  const existing = await internalLoadById<BasicStoreEntity>(context, SYSTEM_USER, id, type ? { type } : undefined);
  return existing ? buildRestrictedEntity(existing) : null;
};

// The stored entity name of a match, unless the reader cannot read the entity
export const readableMatchEntityName = async (context: AuthContext, match: { match_entity_id: string; match_entity_type: string; match_entity_name?: string | null }) => {
  const readable = await loadAsReader(context, match.match_entity_id, match.match_entity_type);
  return readable ? (match.match_entity_name ?? null) : RESTRICTED_NAME;
};
