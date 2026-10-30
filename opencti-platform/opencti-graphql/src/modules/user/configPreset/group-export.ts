import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreEntity } from '../../../types/store';
import { getEntitiesMapFromCache } from '../../../database/cache';
import { storeLoadById } from '../../../database/middleware-loader';
import { groupAllowedMarkings } from '../../../domain/group';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../schema/stixMetaObject';
import { SYSTEM_USER } from '../../../utils/access';
import { ENTITY_TYPE_WORKSPACE } from '../../workspace/workspace-types';
import type { BasicStoreEntityRole } from './role-export';
import type { GroupImportConfiguration, GroupMarkingReference } from './group-import-schema';

export type BasicStoreEntityGroup = BasicStoreEntity & {
  name: string;
  description?: string;
  default_assignation?: boolean;
  auto_integration_assignation?: string[];
  no_creators?: boolean;
  restrict_delete?: boolean;
  auto_new_marking?: boolean;
  group_confidence_level?: GroupImportConfiguration['group_confidence_level'];
  default_hidden_types?: string[];
  default_dashboard?: string;
  default_marking?: { entity_type: string; values?: string[] }[];
  max_shareable_markings?: { type: string; value: string }[];
};

type BasicStoreMarking = BasicStoreEntity & { definition_type: string; definition: string };

const toMarkingReference = (marking: BasicStoreMarking): GroupMarkingReference => ({
  standard_id: marking.standard_id,
  definition_type: marking.definition_type,
  definition: marking.definition,
});

const byName = <T extends { name: string }>(a: T, b: T) => a.name.localeCompare(b.name);

export const getGroupConfigPresetConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  group: BasicStoreEntityGroup,
  roles: BasicStoreEntityRole[],
): Promise<GroupImportConfiguration> => {
  const [allowedMarkings, markings, dashboard] = await Promise.all([
    groupAllowedMarkings(context, user, group.id) as Promise<BasicStoreMarking[]>,
    getEntitiesMapFromCache<BasicStoreMarking>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION),
    group.default_dashboard ? storeLoadById<BasicStoreEntity>(context, user, group.default_dashboard, ENTITY_TYPE_WORKSPACE) : undefined,
  ]);
  const toReferences = (ids: string[] = []) => ids.flatMap((id) => {
    const marking = markings.get(id);
    return marking ? [toMarkingReference(marking)] : [];
  });
  return {
    name: group.name,
    description: group.description ?? '',
    default_assignation: group.default_assignation ?? false,
    auto_integration_assignation: group.auto_integration_assignation ?? [],
    no_creators: group.no_creators ?? false,
    restrict_delete: group.restrict_delete ?? false,
    auto_new_marking: group.auto_new_marking ?? false,
    group_confidence_level: group.group_confidence_level ?? null,
    default_hidden_types: [...(group.default_hidden_types ?? [])].sort(),
    default_dashboard: dashboard ? { standard_id: dashboard.standard_id, name: dashboard.name } : null,
    roles: [...roles].sort(byName).map((role) => ({ standard_id: role.standard_id, name: role.name })),
    allowed_markings: allowedMarkings.map(toMarkingReference).sort((a, b) => a.standard_id.localeCompare(b.standard_id)),
    default_marking: (group.default_marking ?? []).map(({ entity_type, values }) => ({ entity_type, values: toReferences(values) })),
    max_shareable_markings: (group.max_shareable_markings ?? []).flatMap<GroupImportConfiguration['max_shareable_markings'][number]>(({ type, value }) => {
      if (value === 'none') {
        return [{ type, value: 'none' }];
      }
      return toReferences([value]).map((reference) => ({ type, value: reference }));
    }),
  };
};
