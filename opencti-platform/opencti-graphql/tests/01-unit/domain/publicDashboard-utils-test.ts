import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { testContext } from '../../utils/testQuery';
import { findWidgetsMaxMarkings } from '../../../src/modules/publicDashboard/publicDashboard-utils';
import type { PublicDashboardCached } from '../../../src/modules/publicDashboard/publicDashboard-types';
import type { AuthUser } from '../../../src/types/user';
import * as cacheModule from '../../../src/database/cache';
import type { BasicStoreIdentifier, StoreMarkingDefinition } from '../../../src/types/store';

const TLP_AMBER = {
  id: 'tlp_amber',
  definition_type: 'TLP',
  definition: 'TLP:AMBER',
  x_opencti_order: 3
} as unknown as StoreMarkingDefinition;
const TLP_GREEN = {
  id: 'tlp_green',
  definition_type: 'TLP',
  definition: 'TLP:GREEN',
  x_opencti_order: 2
} as unknown as StoreMarkingDefinition;
const TLP_CLEAR = {
  id: 'tlp_clear',
  definition_type: 'TLP',
  definition: 'TLP:CLEAR',
  x_opencti_order: 1
} as unknown as StoreMarkingDefinition;

const TEST_AMBER = {
  id: 'test_amber',
  definition_type: 'TEST',
  definition: 'TEST:AMBER',
  x_opencti_order: 3
} as unknown as StoreMarkingDefinition;
const TEST_GREEN = {
  id: 'test_green',
  definition_type: 'TEST',
  definition: 'TEST:GREEN',
  x_opencti_order: 2
} as unknown as StoreMarkingDefinition;
const TEST_CLEAR = {
  id: 'test_clear',
  definition_type: 'TEST',
  definition: 'TEST:CLEAR',
  x_opencti_order: 1
} as unknown as StoreMarkingDefinition;

const PUBLIC_DASHBOARD = {
  uri_key: 'my-super-dashboard',
  allowed_markings: [TLP_GREEN, TEST_GREEN],
} as unknown as PublicDashboardCached;

const AUTHOR_DASHBOARD = {
  name: 'Jean',
  allowed_marking: [TLP_GREEN, TEST_GREEN],
  max_shareable_marking: [TLP_GREEN, TEST_GREEN],
} as unknown as AuthUser;

describe('publicDashboard-utils', () => {
  describe('findWidgetsMaxMarkings', () => {
    beforeAll(() => {
      vi.spyOn(cacheModule, 'getEntitiesListFromCache')
        .mockImplementation(async () => [
          TLP_AMBER, TLP_GREEN, TLP_CLEAR,
          TEST_AMBER, TEST_GREEN, TEST_CLEAR
        ] as unknown as BasicStoreIdentifier[]);
    });
    afterAll(() => {
      vi.resetAllMocks();
    });

    it('should return the correspond marking if all the same', async () => {
      const markings = await findWidgetsMaxMarkings(testContext, PUBLIC_DASHBOARD, AUTHOR_DASHBOARD);
      const ids = markings.map((marking) => marking.id);
      expect(ids).not.toContain('tlp_amber');
      expect(ids).toContain('tlp_green');
      expect(ids).toContain('tlp_clear');
      expect(ids).not.toContain('test_amber');
      expect(ids).toContain('test_green');
      expect(ids).toContain('test_clear');
    });

    it('should return data sharing marking if data sharing is the min', async () => {
      PUBLIC_DASHBOARD.allowed_markings = [TLP_AMBER, TEST_AMBER];
      AUTHOR_DASHBOARD.allowed_marking = [TLP_AMBER, TEST_AMBER];
      const markings = await findWidgetsMaxMarkings(testContext, PUBLIC_DASHBOARD, AUTHOR_DASHBOARD);
      const ids = markings.map((marking) => marking.id);
      expect(ids).not.toContain('tlp_amber');
      expect(ids).toContain('tlp_green');
      expect(ids).toContain('tlp_clear');
      expect(ids).not.toContain('test_amber');
      expect(ids).toContain('test_green');
      expect(ids).toContain('test_clear');
    });

    it('should return dashboard marking if dashboard is the min', async () => {
      PUBLIC_DASHBOARD.allowed_markings = [TLP_CLEAR, TEST_CLEAR];
      AUTHOR_DASHBOARD.allowed_marking = [TLP_AMBER, TEST_AMBER];
      const markings = await findWidgetsMaxMarkings(testContext, PUBLIC_DASHBOARD, AUTHOR_DASHBOARD);
      const ids = markings.map((marking) => marking.id);
      expect(ids).not.toContain('tlp_amber');
      expect(ids).not.toContain('tlp_green');
      expect(ids).toContain('tlp_clear');
      expect(ids).not.toContain('test_amber');
      expect(ids).not.toContain('test_green');
      expect(ids).toContain('test_clear');
    });

    it('should return user marking if user is the min', async () => {
      PUBLIC_DASHBOARD.allowed_markings = [TLP_AMBER, TEST_AMBER];
      AUTHOR_DASHBOARD.allowed_marking = [TLP_GREEN, TEST_CLEAR];
      const markings = await findWidgetsMaxMarkings(testContext, PUBLIC_DASHBOARD, AUTHOR_DASHBOARD);
      const ids = markings.map((marking) => marking.id);
      expect(ids).not.toContain('tlp_amber');
      expect(ids).toContain('tlp_green');
      expect(ids).toContain('tlp_clear');
      expect(ids).not.toContain('test_amber');
      expect(ids).not.toContain('test_green');
      expect(ids).toContain('test_clear');
    });

    it('should return no marking for a type if dashboard does not contain any', async () => {
      PUBLIC_DASHBOARD.allowed_markings = [TLP_AMBER];
      AUTHOR_DASHBOARD.allowed_marking = [TLP_GREEN, TEST_GREEN];
      const markings = await findWidgetsMaxMarkings(testContext, PUBLIC_DASHBOARD, AUTHOR_DASHBOARD);
      const ids = markings.map((marking) => marking.id);
      expect(ids).not.toContain('tlp_amber');
      expect(ids).toContain('tlp_green');
      expect(ids).toContain('tlp_clear');
      expect(ids).not.toContain('test_amber');
      expect(ids).not.toContain('test_green');
      expect(ids).not.toContain('test_clear');
    });

    it('should return no marking for a type if user does not contain any', async () => {
      PUBLIC_DASHBOARD.allowed_markings = [TLP_GREEN, TEST_GREEN];
      AUTHOR_DASHBOARD.allowed_marking = [];
      const markings = await findWidgetsMaxMarkings(testContext, PUBLIC_DASHBOARD, AUTHOR_DASHBOARD);
      const ids = markings.map((marking) => marking.id);
      expect(ids).not.toContain('tlp_amber');
      expect(ids).not.toContain('tlp_green');
      expect(ids).not.toContain('tlp_clear');
      expect(ids).not.toContain('test_amber');
      expect(ids).not.toContain('test_green');
      expect(ids).not.toContain('test_clear');
    });
  });
});
