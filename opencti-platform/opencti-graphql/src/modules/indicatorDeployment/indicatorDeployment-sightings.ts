import type { AuthContext } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { fullEntitiesList } from '../../database/middleware-loader';
import { SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_IOC_VALIDATION_REQUEST } from '../iocValidation/iocValidation-types';
import { hitsSightingStixId, validationResultSightingStixId } from './indicatorDeployment-utils';

type PairEnd = { entity_type?: string; internal_id?: string };

export type GeneratedPairSightingKind = 'hits' | 'validation_result';

// The (indicator, security platform) pair of a sighting or of a sighting input, when it is one.
export const sightingPair = (element: Record<string, unknown> | undefined) => {
  const from = element?.from as PairEnd | undefined;
  const to = element?.to as PairEnd | undefined;
  if (from?.entity_type !== ENTITY_TYPE_INDICATOR || to?.entity_type !== ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM || !from.internal_id || !to.internal_id) {
    return undefined;
  }
  return { indicatorId: from.internal_id, platformId: to.internal_id };
};

/**
 * Which sighting the platform generates for an (indicator, security platform) pair the sighting is, given the STIX ids it
 * holds or claims: the hits sighting of the pair, or the result sighting of a validation request that included it (both
 * identified by their deterministic id), or undefined for any other sighting.
 */
export const generatedPairSightingKindOf = async (
  context: AuthContext,
  element: Record<string, unknown> | undefined,
  stixIds: string[],
): Promise<GeneratedPairSightingKind | undefined> => {
  const pair = sightingPair(element);
  if (!pair || stixIds.length === 0) {
    return undefined;
  }
  const { indicatorId, platformId } = pair;
  const ids = new Set(stixIds);
  if (ids.has(hitsSightingStixId(indicatorId, platformId))) {
    return 'hits';
  }
  let generated = false;
  await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, [ENTITY_TYPE_IOC_VALIDATION_REQUEST], {
    filters: { mode: 'and', filters: [{ key: ['indicator_ids'], values: [indicatorId] }, { key: ['platform_ids'], values: [platformId] }], filterGroups: [] },
    noFiltersChecking: true,
    baseData: true,
    first: 500,
    callback: async (requests: BasicStoreEntity[]) => {
      generated = requests.some((request) => ids.has(validationResultSightingStixId(request.internal_id, indicatorId, platformId)));
      return !generated;
    },
  } as never);
  return generated ? 'validation_result' : undefined;
};

// STIX ids a sighting creation or upsert supplies (the generic creation accepts a supplied id).
export const suppliedStixIds = (input: Record<string, unknown>) => [input.stix_id, ...((input.x_opencti_stix_ids as string[] | undefined) ?? [])]
  .filter((id): id is string => typeof id === 'string');

/** Which generated sighting of its pair a sighting creation or upsert claims to be, by the STIX id it supplies. */
export const claimedGeneratedPairSighting = (context: AuthContext, input: Record<string, unknown>) => {
  return generatedPairSightingKindOf(context, input, suppliedStixIds(input));
};
