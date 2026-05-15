import { ENTITY_TYPE_DRAFT_ENTITY_READ, type BasicStoreEntityDraftEntityRead, type StoreEntityDraftEntityRead } from './draftEntityRead-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { createInternalObject } from '../../domain/internalObject';
import { patchAttribute } from '../../database/middleware';
import { fullEntitiesList } from '../../database/middleware-loader';
import { addFilter } from '../../utils/filtering/filtering-utils';

// Find the DraftEntityRead record for the current user + entity + draft
export const findDraftEntityRead = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  draftId: string,
): Promise<BasicStoreEntityDraftEntityRead | undefined> => {
  let filters = addFilter(null, 'user_id', user.id);
  filters = addFilter(filters, 'entity_id', entityId);
  filters = addFilter(filters, 'draft_id', draftId);
  const results = await fullEntitiesList<BasicStoreEntityDraftEntityRead>(context, user, [ENTITY_TYPE_DRAFT_ENTITY_READ], { filters });
  return results.at(0);
};

// Mark the entity as read by the current user in the draft
// Upsert: the deterministic standard_id (uuidv5 on user_id|draft_id|entity_id) ensures
// concurrent calls resolve to the same document without a prior find.
export const draftEntityMarkRead = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  draftId: string,
): Promise<StoreEntityDraftEntityRead> => {
  const input = { user_id: user.id, draft_id: draftId, entity_id: entityId, is_read: true };
  // Force creation outside of any draft context to store in live index
  const contextOutOfDraft = { ...context, draft_context: '' };
  return createInternalObject<StoreEntityDraftEntityRead>(contextOutOfDraft, user, input, ENTITY_TYPE_DRAFT_ENTITY_READ, { auditLogEnabled: false });
};

// Mark the entity as unread by the current user in the draft
export const draftEntityMarkUnread = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  draftId: string,
): Promise<StoreEntityDraftEntityRead | null> => {
  const existing = await findDraftEntityRead(context, user, entityId, draftId);
  if (!existing) return null;
  const { element } = await patchAttribute<StoreEntityDraftEntityRead>(context, user, existing.id, ENTITY_TYPE_DRAFT_ENTITY_READ, { is_read: false });
  return element;
};

// Reset read status for ALL users for a given entity+draft (called when entity is re-modified in the draft)
export const resetDraftEntityRead = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  draftId: string,
): Promise<void> => {
  let filters = addFilter(null, 'entity_id', entityId);
  filters = addFilter(filters, 'draft_id', draftId);
  filters = addFilter(filters, 'is_read', 'true');
  const records = await fullEntitiesList<BasicStoreEntityDraftEntityRead>(context, user, [ENTITY_TYPE_DRAFT_ENTITY_READ], { filters });
  await Promise.all(
    records.map((record) => patchAttribute<StoreEntityDraftEntityRead>(context, user, record.id, ENTITY_TYPE_DRAFT_ENTITY_READ, { is_read: false })),
  );
};
