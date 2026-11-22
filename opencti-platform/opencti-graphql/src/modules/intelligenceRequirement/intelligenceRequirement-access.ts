import type { AuthContext, AuthUser } from '../../types/user';
import { storeLoadById } from '../../database/middleware-loader';
import { getUserAccessRight, MEMBER_ACCESS_RIGHT_ADMIN, MEMBER_ACCESS_RIGHT_EDIT } from '../../utils/access';
import { ForbiddenAccess, FunctionalError } from '../../config/errors';
import { type BasicStoreEntityIntelligenceRequirement, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT } from './intelligenceRequirement-types';

/**
 * Segregation of a requirement's content.
 * Matches and inbox items are internal objects without authorized members of their own: they inherit the access of
 * their requirement. A reader who cannot load the requirement (authorized members, markings) sees nothing of it,
 * as if it did not exist; a change (decision, status) needs the edit right on the requirement.
 */
export const IR_ACCESS_READ = 'read';
export const IR_ACCESS_EDIT = 'edit';
type IrAccess = typeof IR_ACCESS_READ | typeof IR_ACCESS_EDIT;

const EDIT_RIGHTS = [MEMBER_ACCESS_RIGHT_ADMIN, MEMBER_ACCESS_RIGHT_EDIT];

export const canEditRequirement = (user: AuthUser, ir: BasicStoreEntityIntelligenceRequirement) => {
  const right = getUserAccessRight(user, ir);
  return right !== null && right !== undefined && EDIT_RIGHTS.includes(right);
};

/**
 * The requirement if the user may read it (or edit it), else null for a read and a ForbiddenAccess for an edit.
 * An unknown requirement and an inaccessible one answer the same way on a read, so its existence is not disclosed.
 */
export const loadRequirementWithAccess = async (context: AuthContext, user: AuthUser, irId: string, access: IrAccess = IR_ACCESS_READ) => {
  const ir = await storeLoadById<BasicStoreEntityIntelligenceRequirement>(context, user, irId, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT);
  if (!ir) {
    if (access === IR_ACCESS_EDIT) throw FunctionalError('Intelligence requirement not found', { id: irId });
    return null;
  }
  if (access === IR_ACCESS_EDIT && !canEditRequirement(user, ir)) throw ForbiddenAccess();
  return ir;
};

// Filters the elements (matches, items) whose requirement the user cannot read; one load per requirement
export const filterByRequirementAccess = async <T extends { ir_id: string }>(context: AuthContext, user: AuthUser, elements: T[]) => {
  const readable = new Map<string, boolean>();
  const result: T[] = [];
  for (let i = 0; i < elements.length; i += 1) {
    const element = elements[i];
    if (!readable.has(element.ir_id)) {
      readable.set(element.ir_id, (await loadRequirementWithAccess(context, user, element.ir_id)) !== null);
    }
    if (readable.get(element.ir_id)) result.push(element);
  }
  return result;
};
