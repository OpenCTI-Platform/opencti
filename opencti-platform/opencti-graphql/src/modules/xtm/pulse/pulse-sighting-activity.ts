import { logApp } from '../../../config/conf';
import { getEntityFromCache } from '../../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../schema/internalObject';
import type { BasicStoreSettings } from '../../../types/settings';
import type { AuthContext } from '../../../types/user';
import { SYSTEM_USER } from '../../../utils/access';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../securityPlatform/securityPlatform-types';
import { redisRecordPulseSightingIncrease } from './pulse-cache';
import { isPulseContributing, readPulseSettings } from './pulse-settings';

interface SightingSides {
  internal_id: string;
  fromId: string;
  fromType: string;
  toType: string;
  created_at?: Date | string;
  attribute_count?: number;
}

const isoDate = (value: Date | string | undefined | null) => {
  const date = value ? new Date(value) : null;
  return date && !Number.isNaN(date.getTime()) ? date : null;
};

// A sighting seen again raises the count of the existing relationship instead of creating one, so the collector, which
// reads the relationships created in its window, never meets it again. The increase is kept as activity of the sighted
// object, contributed by the next hourly run: a detection when a security platform saw it. A sighting whose window has
// still to be collected carries the increase in the count that window reads: its new total is kept for the commit of
// that window instead (redisRecordPulseSightingIncrease), so an upsert racing with the window counts once.
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
    // Without a cursor yet, the first window starts at the consent; no window ever reads before the oldest accepted day.
    const now = new Date();
    const oldestAccepted = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - 1));
    const consent = isoDate(values.consentDate);
    const oldestCollected = consent && consent.getTime() > oldestAccepted.getTime() ? consent : oldestAccepted;
    await redisRecordPulseSightingIncrease({
      id: sighting.internal_id,
      createdAt: isoDate(sighting.created_at)?.toISOString() ?? '',
      oldestCollected: oldestCollected.toISOString(),
      total: Number(sighting.attribute_count ?? 0) + increase,
      increase,
      entityId: sighting.fromId,
      eventKind: sighting.toType === ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM ? 'detected' : 'sighted',
    });
  } catch (error) {
    // The sighting is recorded whatever happens to its Threat Pulse activity.
    logApp.warn('[THREAT PULSE] Activity of a sighting seen again not recorded', { cause: error });
  }
};
