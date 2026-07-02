import type { AuthContext, AuthUser } from '../../types/user';
import { patchAttribute } from '../../database/middleware';
import type { DataSanityConfigurationObject, DayOfWeek, MaintenancePlanning, MaintenanceWindow } from './dataSanityConfiguration-types';
import { utcDate } from '../../utils/format';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { getEntityFromCache } from '../../database/cache';
import type { BasicStoreSettings } from '../../types/settings';

const DAYS_OF_WEEK: DayOfWeek[] = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];

/**
 * Retrieve the data_sanity_configuration object from the Settings entity.
 */
export const getDataSanityConfigurationFromSettings = async (context: AuthContext, user: AuthUser): Promise<DataSanityConfigurationObject | undefined> => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  if (!settings) {
    return undefined;
  }
  return (settings as any).data_sanity_configuration as DataSanityConfigurationObject | undefined;
};

/**
 * Get the maintenance planning from configuration.
 * Returns an empty array if no configuration exists.
 */
export const getMaintenancePlanning = async (context: AuthContext, user: AuthUser): Promise<MaintenancePlanning> => {
  const config = await getDataSanityConfigurationFromSettings(context, user);
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
 * Update the data_sanity_configuration object in Settings with a new maintenance planning.
 */
export const updateMaintenancePlanning = async (context: AuthContext, user: AuthUser, planning: MaintenancePlanning, timezoneOffset: number) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  if (!settings) {
    throw new Error('Settings entity not found');
  }
  const planningJson = JSON.stringify(planning);
  const patch = {
    data_sanity_configuration: {
      maintenance_planning: planningJson,
      timezone_offset: timezoneOffset,
    } as DataSanityConfigurationObject,
  };
  await patchAttribute(context, user, settings.internal_id, ENTITY_TYPE_SETTINGS, patch);
  return { maintenance_planning: planning, timezone_offset: timezoneOffset };
};

/**
 * Get the DataSanityConfiguration formatted for GraphQL response.
 * Returns null if no configuration exists.
 */
export const getDataSanityConfiguration = async (context: AuthContext, user: AuthUser) => {
  const config = await getDataSanityConfigurationFromSettings(context, user);
  if (!config) {
    return null;
  }
  let planning: MaintenancePlanning = [];
  if (config.maintenance_planning) {
    try {
      planning = JSON.parse(config.maintenance_planning) as MaintenancePlanning;
    } catch {
      planning = [];
    }
  }
  return { maintenance_planning: planning, timezone_offset: config.timezone_offset ?? 0 };
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
 * Check if the current time is within a maintenance window.
 * Times are evaluated in the configured timezone (via timezone_offset).
 * If no maintenance planning is configured, operations are always allowed.
 */
export const isWithinMaintenanceWindow = async (context: AuthContext, user: AuthUser): Promise<boolean> => {
  const config = await getDataSanityConfigurationFromSettings(context, user);
  if (!config?.maintenance_planning) {
    return true;
  }
  let planning: MaintenancePlanning;
  try {
    planning = JSON.parse(config.maintenance_planning) as MaintenancePlanning;
  } catch {
    return true;
  }
  if (planning.length === 0) {
    return true;
  }
  // Apply timezone offset to get the "local" time as configured by the user
  const timezoneOffset = config.timezone_offset ?? 0;
  const now = utcDate().utcOffset(timezoneOffset);
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
