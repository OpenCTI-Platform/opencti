import type { AuthContext, AuthUser } from '../../types/user';
import { fullEntitiesList } from '../../database/middleware-loader';
import { createEntity, updateAttribute } from '../../database/middleware';
import { ENTITY_TYPE_DATA_SANITY_CONFIGURATION } from './dataSanityConfiguration-types';
import type { BasicStoreEntityDataSanityConfiguration, DayOfWeek, MaintenancePlanning, MaintenanceWindow } from './dataSanityConfiguration-types';
import { utcDate } from '../../utils/format';

const DAYS_OF_WEEK: DayOfWeek[] = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];

/**
 * Retrieve the single DataSanityConfiguration entity (singleton pattern).
 */
export const getDataSanityConfigurationFromDatabase = async (context: AuthContext, user: AuthUser): Promise<BasicStoreEntityDataSanityConfiguration | undefined> => {
  const results = await fullEntitiesList<BasicStoreEntityDataSanityConfiguration>(
    context,
    user,
    [ENTITY_TYPE_DATA_SANITY_CONFIGURATION],
    {},
  );
  return results.length > 0 ? results[0] : undefined;
};

/**
 * Get the maintenance planning from configuration.
 * Returns an empty array if no configuration exists.
 */
export const getMaintenancePlanning = async (context: AuthContext, user: AuthUser): Promise<MaintenancePlanning> => {
  const config = await getDataSanityConfigurationFromDatabase(context, user);
  if (!config?.maintenance_planning) {
    return [];
  }
  try {
    return JSON.parse(config.maintenance_planning) as MaintenancePlanning;
  } catch {
    return [];
  }
};

/**
 * Update or create the DataSanityConfiguration with a new maintenance planning.
 */
export const updateMaintenancePlanning = async (context: AuthContext, user: AuthUser, planning: MaintenancePlanning) => {
  const existing = await getDataSanityConfigurationFromDatabase(context, user);
  const planningJson = JSON.stringify(planning);
  if (existing) {
    await updateAttribute(context, user, existing.internal_id, ENTITY_TYPE_DATA_SANITY_CONFIGURATION, [
      { key: 'maintenance_planning', value: [planningJson] },
    ]);
    return { id: existing.internal_id, maintenance_planning: planning };
  }
  const created = await createEntity(context, user, {
    maintenance_planning: planningJson,
  }, ENTITY_TYPE_DATA_SANITY_CONFIGURATION);
  return { id: created.internal_id, maintenance_planning: planning };
};

/**
 * Get the DataSanityConfiguration formatted for GraphQL response.
 * Returns null if no configuration exists.
 */
export const getDataSanityConfiguration = async (context: AuthContext, user: AuthUser) => {
  const config = await getDataSanityConfigurationFromDatabase(context, user);
  if (!config) {
    return null;
  }
  const planning = await getMaintenancePlanning(context, user);
  return { id: config.internal_id, maintenance_planning: planning };
};

/**
 * Parse a "HH:mm" time string into total minutes since midnight.
 * Throws if the format is invalid.
 */
export const parseTimeToMinutes = (time: string): number => {
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) {
    throw new Error(`Invalid time format: "${time}". Expected HH:mm (00:00 to 23:59).`);
  }
  const [hours, minutes] = time.split(':').map(Number);
  return hours * 60 + minutes;
};

/**
 * Check if the current time (UTC) is within a maintenance window.
 * If no maintenance planning is configured, operations are always allowed.
 */
export const isWithinMaintenanceWindow = async (context: AuthContext, user: AuthUser): Promise<boolean> => {
  const planning = await getMaintenancePlanning(context, user);
  // If no planning is configured, always allow operations
  if (planning.length === 0) {
    return true;
  }
  const now = utcDate();
  const currentDay = DAYS_OF_WEEK[now.day()] as DayOfWeek;
  const currentMinutes = now.hour() * 60 + now.minute();
  return planning.some((window: MaintenanceWindow) => {
    if (window.day !== currentDay) {
      return false;
    }
    const startMinutes = parseTimeToMinutes(window.start_time);
    const endMinutes = parseTimeToMinutes(window.end_time);
    // Support windows that span midnight (e.g., start_time: "22:30", end_time: "04:15")
    if (startMinutes <= endMinutes) {
      return currentMinutes >= startMinutes && currentMinutes < endMinutes;
    }
    // Wraps midnight
    return currentMinutes >= startMinutes || currentMinutes < endMinutes;
  });
};
