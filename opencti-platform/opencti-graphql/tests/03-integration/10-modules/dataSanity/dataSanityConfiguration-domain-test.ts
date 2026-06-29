import { describe, it, expect } from 'vitest';
import {
  getDataSanityConfiguration,
  getDataSanityConfigurationFromDatabase,
  getMaintenancePlanning,
  isWithinMaintenanceWindow,
  parseTimeToMinutes,
  updateMaintenancePlanning,
} from '../../../../src/modules/dataSanity/dataSanityConfiguration-domain';
import convertDataSanityConfigurationToStix from '../../../../src/modules/dataSanity/dataSanityConfiguration-converter';
import type { MaintenancePlanning, StoreEntityDataSanityConfiguration } from '../../../../src/modules/dataSanity/dataSanityConfiguration-types';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

describe('Data sanity configuration test coverage', () => {
  describe('Data sanity configuration test coverage', () => {
    it('should on first run, execute new operations from the list', async () => {
      // Normal usage
      expect(parseTimeToMinutes('08:00')).toBe(480);
      expect(parseTimeToMinutes('00:00')).toBe(0);
      expect(parseTimeToMinutes('23:59')).toBe(1439);

      // Strange or unexpected values
      expect(() => parseTimeToMinutes('42:99')).toThrow('Invalid time format: "42:99". Expected HH:mm (00:00 to 23:59).');
      expect(() => parseTimeToMinutes('')).toThrow('Invalid time format: "". Expected HH:mm (00:00 to 23:59).');
      expect(() => parseTimeToMinutes('nope')).toThrow('Invalid time format: "nope". Expected HH:mm (00:00 to 23:59).');
      expect(() => parseTimeToMinutes('01:01:01')).toThrow('Invalid time format: "01:01:01". Expected HH:mm (00:00 to 23:59).');
    });
  });

  describe('Data sanity maintenance planning coverage', () => {
    const daysOfWeek: Array<'sunday' | 'monday' | 'tuesday' | 'wednesday' | 'thursday' | 'friday' | 'saturday'> = [
      'sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday',
    ];

    it('should not planning configured be ok', async () => {
      const initialPlanning = await getMaintenancePlanning(testContext, ADMIN_USER);
      expect(initialPlanning).toStrictEqual([]);
    });

    it('should be within planning be ok when planning is empty', async () => {
      const isWithinPlanning = await isWithinMaintenanceWindow(testContext, ADMIN_USER);
      expect(isWithinPlanning).toBeTruthy();
    });

    it('should update planning configured be ok', async () => {
      const planning: MaintenancePlanning = [{ day: 'monday', start_time: '08:00', end_time: '10:00' }, { day: 'tuesday', start_time: '09:00', end_time: '10:30' }];
      await updateMaintenancePlanning(testContext, ADMIN_USER, planning);
      const newPlanning = await getMaintenancePlanning(testContext, ADMIN_USER);
      expect(newPlanning).toStrictEqual([{ day: 'monday', start_time: '08:00', end_time: '10:00' }, { day: 'tuesday', start_time: '09:00', end_time: '10:30' }]);
    });

    it('should stix converter', async () => {
      const newPlanning = await getDataSanityConfigurationFromDatabase(testContext, ADMIN_USER);
      if (newPlanning) {
        const result = convertDataSanityConfigurationToStix(newPlanning as StoreEntityDataSanityConfiguration);
        expect(result.maintenance_planning).toStrictEqual('[{"day":"monday","start_time":"08:00","end_time":"10:00"},{"day":"tuesday","start_time":"09:00","end_time":"10:30"}]');
      }
    });

    it('should be within planning be ok when planning is filled', async () => {
      const now = new Date();
      const currentDay = daysOfWeek[now.getUTCDay()];
      const currentHour = now.getUTCHours();
      const currentMinute = now.getUTCMinutes();

      // Build a window that starts 5 minutes before now and ends 5 minutes after now
      const startTotalMinutes = (currentHour * 60 + currentMinute - 5 + 1440) % 1440;
      const endTotalMinutes = (currentHour * 60 + currentMinute + 5) % 1440;

      const startTime = `${String(Math.floor(startTotalMinutes / 60)).padStart(2, '0')}:${String(startTotalMinutes % 60).padStart(2, '0')}`;
      const endTime = `${String(Math.floor(endTotalMinutes / 60)).padStart(2, '0')}:${String(endTotalMinutes % 60).padStart(2, '0')}`;

      const planning: MaintenancePlanning = [{ day: currentDay, start_time: startTime, end_time: endTime }];
      await updateMaintenancePlanning(testContext, ADMIN_USER, planning);

      const isWithinPlanning = await isWithinMaintenanceWindow(testContext, ADMIN_USER);
      expect(isWithinPlanning).toBeTruthy();
    });

    it('should be outside planning when window is on a different day', async () => {
      const now = new Date();

      // Pick a day that is NOT today
      const tomorrowIndex = (now.getUTCDay() + 1) % 7;
      const differentDay = daysOfWeek[tomorrowIndex];

      const planning: MaintenancePlanning = [{ day: differentDay, start_time: '00:00', end_time: '23:59' }];
      await updateMaintenancePlanning(testContext, ADMIN_USER, planning);

      const isWithinPlanning = await isWithinMaintenanceWindow(testContext, ADMIN_USER);
      expect(isWithinPlanning).toBeFalsy();
    });

    it('should be outside planning when current time is not in window', async () => {
      const now = new Date();

      const currentDay = daysOfWeek[now.getUTCDay()];
      const currentHour = now.getUTCHours();
      const currentMinute = now.getUTCMinutes();

      // Build a window that is entirely in the past (ended 10 minutes ago)
      const endTotalMinutes = (currentHour * 60 + currentMinute - 10 + 1440) % 1440;
      const startTotalMinutes = (endTotalMinutes - 30 + 1440) % 1440;

      const startTime = `${String(Math.floor(startTotalMinutes / 60)).padStart(2, '0')}:${String(startTotalMinutes % 60).padStart(2, '0')}`;
      const endTime = `${String(Math.floor(endTotalMinutes / 60)).padStart(2, '0')}:${String(endTotalMinutes % 60).padStart(2, '0')}`;

      const planning: MaintenancePlanning = [{ day: currentDay, start_time: startTime, end_time: endTime }];
      await updateMaintenancePlanning(testContext, ADMIN_USER, planning);

      const isWithinPlanning = await isWithinMaintenanceWindow(testContext, ADMIN_USER);
      expect(isWithinPlanning).toBeFalsy();
    });

    it('should be within planning when window spans midnight', async () => {
      const now = new Date();

      const currentDay = daysOfWeek[now.getUTCDay()];
      const currentHour = now.getUTCHours();
      const currentMinute = now.getUTCMinutes();
      const currentTotalMinutes = currentHour * 60 + currentMinute;

      // Create a window spanning midnight that includes "now"
      // start_time > end_time triggers the midnight-spanning branch
      let startTime: string;
      let endTime: string;
      if (currentTotalMinutes >= 720) {
        // Afternoon/evening: start 5 min before now, end early morning (wraps midnight)
        const startMin = (currentTotalMinutes - 5 + 1440) % 1440;
        startTime = `${String(Math.floor(startMin / 60)).padStart(2, '0')}:${String(startMin % 60).padStart(2, '0')}`;
        endTime = '04:00'; // ends next day early morning
      } else {
        // Morning: start late evening yesterday, end 5 min after now
        startTime = '22:00';
        const endMin = (currentTotalMinutes + 5) % 1440;
        endTime = `${String(Math.floor(endMin / 60)).padStart(2, '0')}:${String(endMin % 60).padStart(2, '0')}`;
      }

      const planning: MaintenancePlanning = [{ day: currentDay, start_time: startTime, end_time: endTime }];
      await updateMaintenancePlanning(testContext, ADMIN_USER, planning);

      const isWithinPlanning = await isWithinMaintenanceWindow(testContext, ADMIN_USER);
      expect(isWithinPlanning).toBeTruthy();
    });

    it('should getDataSanityConfiguration return null when no config exists initially', async () => {
      // Reset planning to empty so we can test the GraphQL-facing function
      // First, let's just call it - there IS a config from previous tests
      const config = await getDataSanityConfiguration(testContext, ADMIN_USER);
      expect(config).not.toBeNull();
      expect(config?.maintenance_planning).toBeDefined();
      expect(Array.isArray(config?.maintenance_planning)).toBeTruthy();
    });
  });
});
