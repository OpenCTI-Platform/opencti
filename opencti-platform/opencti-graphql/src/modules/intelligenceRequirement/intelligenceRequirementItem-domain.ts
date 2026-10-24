import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { type EntityOptions, fullEntitiesList, internalLoadById, pageEntitiesConnection } from '../../database/middleware-loader';
import { createEntity, patchAttribute } from '../../database/middleware';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { enforceEnableFeatureFlag } from '../../utils/access';
import { INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG } from '../../config/conf';
import { OrderingMode } from '../../generated/graphql';
import { type BasicStoreEntityIntelligenceRequirementItem, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM, type StoreIrItemData } from './intelligenceRequirementItem-types';

export const parseItemData = (item: BasicStoreEntityIntelligenceRequirementItem): StoreIrItemData => {
  try {
    return JSON.parse(item.item_data ?? '{}');
  } catch {
    return {};
  }
};

export const entityDisplayName = async (context: AuthContext, user: AuthUser, entityId: string) => {
  const entity = await internalLoadById<BasicStoreEntity>(context, user, entityId);
  return entity ? extractEntityRepresentativeName(entity) : entityId;
};

export const createItem = async (
  context: AuthContext,
  user: AuthUser,
  irId: string,
  kind: string,
  title: string,
  opts: { entityId?: string; entityType?: string; matchId?: string; data?: StoreIrItemData } = {},
) => {
  const input = {
    ir_id: irId,
    item_kind: kind,
    item_status: 'open',
    item_title: title,
    item_entity_id: opts.entityId ?? null,
    item_entity_type: opts.entityType ?? null,
    item_match_id: opts.matchId ?? null,
    item_data: JSON.stringify(opts.data ?? {}),
    item_result: null,
  };
  return createEntity(context, user, input, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM);
};

export const findItemsPaginated = async (
  context: AuthContext,
  user: AuthUser,
  irId: string,
  opts: EntityOptions<BasicStoreEntityIntelligenceRequirementItem> & { statuses?: string[] | null; kinds?: string[] | null } = {},
) => {
  enforceEnableFeatureFlag(INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG);
  const { statuses, kinds, ...listOpts } = opts;
  let filters = addFilter(listOpts.filters, 'ir_id', irId);
  if (statuses && statuses.length > 0) filters = addFilter(filters, 'item_status', statuses);
  if (kinds && kinds.length > 0) filters = addFilter(filters, 'item_kind', kinds);
  return pageEntitiesConnection<BasicStoreEntityIntelligenceRequirementItem>(context, user, [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM], {
    orderBy: 'created_at',
    orderMode: OrderingMode.Desc,
    ...listOpts,
    filters,
  });
};

export const closeItem = async (context: AuthContext, user: AuthUser, itemId: string, result: string) => {
  const { element } = await patchAttribute(context, user, itemId, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM, { item_status: 'done', item_result: result });
  return element as unknown as BasicStoreEntityIntelligenceRequirementItem;
};

// Close the open items of an entity of the requirement (optionally only one kind)
export const closeOpenItemsOfMatch = async (context: AuthContext, user: AuthUser, irId: string, matchId: string, result: string, kind?: string) => {
  let filters = addFilter(addFilter(addFilter(undefined, 'ir_id', irId), 'item_match_id', matchId), 'item_status', 'open');
  if (kind) filters = addFilter(filters, 'item_kind', kind);
  const items = await fullEntitiesList<BasicStoreEntityIntelligenceRequirementItem>(context, user, [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM], { filters });
  for (let i = 0; i < items.length; i += 1) {
    await closeItem(context, user, items[i].id, result);
  }
};
