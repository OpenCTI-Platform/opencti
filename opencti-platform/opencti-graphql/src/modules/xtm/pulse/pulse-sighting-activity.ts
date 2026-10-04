import { logApp } from '../../../config/conf';
import { getEntityFromCache } from '../../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../schema/internalObject';
import type { BasicStoreSettings } from '../../../types/settings';
import type { AuthContext } from '../../../types/user';
import { SYSTEM_USER } from '../../../utils/access';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../securityPlatform/securityPlatform-types';
import { redisAddPulseActivity } from './pulse-cache';
import { isPulseContributing, readPulseSettings } from './pulse-settings';

interface SightingSides {
  fromId: string;
  fromType: string;
  toType: string;
}

// A sighting seen again raises the count of the existing relationship instead of creating one, so the collector, which
// reads the relationships created in its window, never meets it again. The increase is kept as activity of the sighted
// object, contributed by the next hourly run: a detection when a security platform saw it.
export const recordPulseSightingIncrease = async (context: AuthContext, sighting: SightingSides, increase: number) => {
  if (increase <= 0) {
    return;
  }
  try {
    const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    const values = readPulseSettings(settings);
    if (!isPulseContributing(values) || !values.scopes.includes(sighting.fromType)) {
      return;
    }
    const kind = sighting.toType === ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM ? 'detected' : 'sighted';
    await redisAddPulseActivity(new Date().toISOString().slice(0, 10), sighting.fromId, kind, increase);
  } catch (error) {
    // The sighting is recorded whatever happens to its Threat Pulse activity.
    logApp.warn('[THREAT PULSE] Activity of a sighting seen again not recorded', { cause: error });
  }
};
