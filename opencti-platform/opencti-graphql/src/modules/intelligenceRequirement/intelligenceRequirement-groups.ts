import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { fullEntitiesList, internalFindByIds } from '../../database/middleware-loader';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { parseIrFilters } from './intelligenceRequirement-config';
import type { ParsedIntelligenceRequirement, StoreIrSubjectGroup } from './intelligenceRequirement-types';

// Members of a subject group: the listed entities, or what its dynamic filter selects today (e.g. every ransomware malware).
// Shared by the scope engine (anchors of the criteria) and by the conditions and rules that reference a group.

export interface IrGroupMembers {
  internalIds: string[];
  allIds: Set<string>; // internal and standard ids
}

const CACHE_TTL = 60 * 1000;
const cache = new Map<string, { at: number; members: IrGroupMembers }>();

export const resolveSubjectGroup = async (context: AuthContext, user: AuthUser, group: StoreIrSubjectGroup): Promise<IrGroupMembers> => {
  const key = JSON.stringify([group.kind, group.entity_ids, group.filters]);
  const cached = cache.get(key);
  if (cached && Date.now() - cached.at < CACHE_TTL) return cached.members;
  let entities: BasicStoreEntity[] = [];
  if (group.kind === 'list' && group.entity_ids.length > 0) {
    entities = await internalFindByIds<BasicStoreEntity>(context, user, group.entity_ids) as BasicStoreEntity[];
  } else if (group.kind === 'filter') {
    const filters = parseIrFilters(group.filters);
    entities = filters ? await fullEntitiesList<BasicStoreEntity>(context, user, [ABSTRACT_STIX_CORE_OBJECT], { filters, baseData: true }) : [];
  }
  const members = {
    internalIds: entities.map((e) => e.internal_id),
    allIds: new Set<string>([...(group.kind === 'list' ? group.entity_ids : []), ...entities.flatMap((e) => [e.internal_id, e.standard_id])]),
  };
  cache.set(key, { at: Date.now(), members });
  return members;
};

// Members of several groups of a requirement, as a set of internal and standard ids (keywords groups have no member)
export const groupMemberSet = async (context: AuthContext, user: AuthUser, ir: ParsedIntelligenceRequirement, groupIds: string[]) => {
  const groups = ir.ir_subject_groups.filter((g) => groupIds.includes(g.id) && g.kind !== 'keywords');
  if (groups.length === 1) return (await resolveSubjectGroup(context, user, groups[0])).allIds;
  const ids = new Set<string>();
  for (let i = 0; i < groups.length; i += 1) {
    (await resolveSubjectGroup(context, user, groups[i])).allIds.forEach((id) => ids.add(id));
  }
  return ids;
};

// Internal ids of the members of several groups of a requirement (keywords groups have no member)
export const groupMemberIds = async (context: AuthContext, user: AuthUser, ir: ParsedIntelligenceRequirement, groupIds: string[]) => {
  const ids = new Set<string>();
  const groups = ir.ir_subject_groups.filter((g) => groupIds.includes(g.id) && g.kind !== 'keywords');
  for (let i = 0; i < groups.length; i += 1) {
    const members = await resolveSubjectGroup(context, user, groups[i]);
    members.internalIds.forEach((id) => ids.add(id));
  }
  return Array.from(ids);
};
