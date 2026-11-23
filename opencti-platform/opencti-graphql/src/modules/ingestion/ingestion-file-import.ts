import { getEntitiesMapFromCache } from '../../database/cache';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import type { BasicStoreEntityMarkingDefinition } from '../../types/store';
import type { AuthContext } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';

// A feed file is the export of one feed, or a feed taken from a configuration bundle (integrations/<type>_feeds/<name>.json).
// The bundle one is told by its type: its configuration is the one of the configuration import, not the one of the feed file.
export const isConfigPresetFeedFile = (parsedData: { type?: unknown } | null | undefined, familyId: string) => {
  return parsedData?.type === `integrations.${familyId}`;
};

// The markings of a bundle feed are referenced by standard id: the ones the platform has, the others are left out
export const resolveFeedFileMarkings = async (context: AuthContext, references: unknown): Promise<BasicStoreEntityMarkingDefinition[]> => {
  if (!Array.isArray(references)) {
    return [];
  }
  const markings = [...(await getEntitiesMapFromCache<BasicStoreEntityMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION)).values()];
  return references
    .map((reference) => markings.find(({ standard_id }) => standard_id === (reference as { standard_id?: unknown } | null)?.standard_id))
    .filter((marking): marking is BasicStoreEntityMarkingDefinition => !!marking)
    .filter((marking, index, all) => all.findIndex(({ id }) => id === marking.id) === index);
};
