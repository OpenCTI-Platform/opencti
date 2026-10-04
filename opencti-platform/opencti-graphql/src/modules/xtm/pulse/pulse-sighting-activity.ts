import { logApp } from '../../../config/conf';
import { getEntityFromCache } from '../../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../schema/internalObject';
import type { BasicStoreSettings } from '../../../types/settings';
import type { AuthContext } from '../../../types/user';
import { SYSTEM_USER } from '../../../utils/access';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../securityPlatform/securityPlatform-types';
import { redisAddPulseActivity, redisGetPulseCursor } from './pulse-cache';
import { isPulseContributing, readPulseSettings } from './pulse-settings';

interface SightingSides {
  fromId: string;
  fromType: string;
  toType: string;
  created_at?: Date | string;
}

// Whether the collector has still to read the sighting: created at or after the start of the next window (the cursor,
// never before the oldest day XTM Hub accepts), it is contributed with the count it has then, increases included.
const isCollectedLater = async (createdAt: Date | string | undefined) => {
  const created = createdAt ? new Date(createdAt).getTime() : Number.NaN;
  const cursor = Date.parse((await redisGetPulseCursor()) ?? '');
  if (Number.isNaN(created) || Number.isNaN(cursor)) {
    return false;
  }
  const now = new Date();
  const oldestAccepted = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - 1);
  return created >= Math.max(cursor, oldestAccepted);
};

// A sighting seen again raises the count of the existing relationship instead of creating one, so the collector, which
// reads the relationships created in its window, never meets it again. The increase is kept as activity of the sighted
// object, contributed by the next hourly run: a detection when a security platform saw it. A sighting the collector has
// not read yet carries the increase in its count, so it is not kept twice.
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
    if (await isCollectedLater(sighting.created_at)) {
      return;
    }
    const kind = sighting.toType === ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM ? 'detected' : 'sighted';
    await redisAddPulseActivity(new Date().toISOString().slice(0, 10), sighting.fromId, kind, increase);
  } catch (error) {
    // The sighting is recorded whatever happens to its Threat Pulse activity.
    logApp.warn('[THREAT PULSE] Activity of a sighting seen again not recorded', { cause: error });
  }
};
