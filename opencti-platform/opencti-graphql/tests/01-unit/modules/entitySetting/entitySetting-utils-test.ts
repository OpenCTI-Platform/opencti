import { describe, expect, it } from 'vitest';
import { fillDefaultValues, isSegregationEntityCheck } from '../../../../src/modules/entitySetting/entitySetting-utils';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, INPUT_GRANTED_REFS } from '../../../../src/schema/general';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY,
} from '../../../../src/schema/stixDomainObject';

// Test fixtures
const TEST_USER_ID = 'user-123';
const TEST_ORG_IDS = ['org-456', 'org-789'];
const CUSTOM_ORG_ID = 'org-custom';

describe('entitySetting-utils', () => {
  describe('isSegregationEntityCheck', () => {
    it('should return true for segregation entities (threat actors, intrusion sets, etc.)', () => {
      expect(isSegregationEntityCheck(ENTITY_TYPE_THREAT_ACTOR_GROUP)).toBe(true);
      expect(isSegregationEntityCheck(ENTITY_TYPE_INTRUSION_SET)).toBe(true);
      expect(isSegregationEntityCheck(ENTITY_TYPE_MALWARE)).toBe(true);
      expect(isSegregationEntityCheck(ENTITY_TYPE_TOOL)).toBe(true);
      expect(isSegregationEntityCheck(ENTITY_TYPE_CAMPAIGN)).toBe(true);
      expect(isSegregationEntityCheck(ENTITY_TYPE_CONTAINER_REPORT)).toBe(true);
    });

    it('should return false for non-segregation entities (locations with parent in unrestricted list)', () => {
      // Individual is NOT in unrestricted list, so it IS a segregation entity
      expect(isSegregationEntityCheck(ENTITY_TYPE_IDENTITY_INDIVIDUAL)).toBe(true);
      // Location parent type IS in unrestricted list, so children are not segregation entities
      expect(isSegregationEntityCheck(ENTITY_TYPE_LOCATION_COUNTRY)).toBe(false);
      expect(isSegregationEntityCheck(ENTITY_TYPE_LOCATION_CITY)).toBe(false);
    });

    it('should return true for restricted entities (attack patterns, vulnerabilities)', () => {
      expect(isSegregationEntityCheck(ENTITY_TYPE_ATTACK_PATTERN)).toBe(true);
      expect(isSegregationEntityCheck(ENTITY_TYPE_VULNERABILITY)).toBe(true);
    });

    it('should handle cyber observables correctly', () => {
      // Cyber observables are not in unrestricted list, so they ARE segregation entities
      // This is because ABSTRACT_STIX_CYBER_OBSERVABLE is not in STIX_ORGANIZATIONS_UNRESTRICTED
      expect(isSegregationEntityCheck(ABSTRACT_STIX_CYBER_OBSERVABLE)).toBe(true);
    });

    it('should throw error for undefined targetType', () => {
      // @ts-expect-error - Testing edge case with undefined
      expect(() => isSegregationEntityCheck(undefined)).toThrow('Type undefined not supported');
    });

    it('should throw error for null targetType', () => {
      // @ts-expect-error - Testing edge case with null
      expect(() => isSegregationEntityCheck(null)).toThrow('Type null not supported');
    });
  });

  describe('fillDefaultValues', () => {
    // Test fixtures
    const mockUser = {
      id: TEST_USER_ID,
      organizations: TEST_ORG_IDS,
    };

    const createMockContext = (user_inside_platform_organization: boolean) => ({
      otp_mandatory: false,
      source: 'test',
      tracing: {},
      user: mockUser,
      user_inside_platform_organization,
    } as any);

    const createEntitySetting = (target_type: string, attributes_configuration: any = null) => ({
      target_type,
      attributes_configuration,
    });

    // Helper to test granted_refs assignment
    const expectGrantedRefs = (result: any, expected: string[] | undefined) => {
      if (expected === undefined) {
        expect(result[INPUT_GRANTED_REFS]).toBeUndefined();
      } else {
        expect(result[INPUT_GRANTED_REFS]).toEqual(expected);
      }
    };

    describe('granted_refs assignment', () => {
      it('should assign user organizations for segregation entities', () => {
        const context = createMockContext(false);
        const setting = createEntitySetting(ENTITY_TYPE_MALWARE);
        const result = fillDefaultValues(context, mockUser, {}, setting);

        expectGrantedRefs(result, TEST_ORG_IDS);
      });

      it('should not assign when user is inside platform organization', () => {
        const context = createMockContext(true);
        const setting = createEntitySetting(ENTITY_TYPE_MALWARE);
        const result = fillDefaultValues(context, mockUser, {}, setting);

        expectGrantedRefs(result, undefined);
      });

      it('should preserve existing granted_refs', () => {
        const context = createMockContext(false);
        const setting = createEntitySetting(ENTITY_TYPE_MALWARE);
        const input = { [INPUT_GRANTED_REFS]: [CUSTOM_ORG_ID] };
        const result = fillDefaultValues(context, mockUser, input, setting);

        expectGrantedRefs(result, [CUSTOM_ORG_ID]);
      });

      it('should preserve explicitly empty granted_refs array', () => {
        const context = createMockContext(false);
        const setting = createEntitySetting(ENTITY_TYPE_MALWARE);
        const input = { [INPUT_GRANTED_REFS]: [] };
        const result = fillDefaultValues(context, mockUser, input, setting);

        expectGrantedRefs(result, []);
      });

      it('should not assign for non-segregation entities', () => {
        const context = createMockContext(false);
        const setting = createEntitySetting(ENTITY_TYPE_LOCATION_COUNTRY);
        const result = fillDefaultValues(context, mockUser, {}, setting);

        expectGrantedRefs(result, undefined);
      });

      it('should not assign when user has no organizations', () => {
        const context = createMockContext(false);
        const setting = createEntitySetting(ENTITY_TYPE_MALWARE);
        const userWithoutOrgs = { id: TEST_USER_ID, organizations: [] };
        const result = fillDefaultValues(context, userWithoutOrgs, {}, setting);

        expectGrantedRefs(result, undefined);
      });

      it('should not assign when entitySetting has no target_type', () => {
        const context = createMockContext(false);
        const setting = { attributes_configuration: null };
        const result = fillDefaultValues(context, mockUser, {}, setting);

        expectGrantedRefs(result, undefined);
      });

      describe('multiple entity types', () => {
        it.each([
          ['threat actors', ENTITY_TYPE_THREAT_ACTOR_GROUP],
          ['intrusion sets', ENTITY_TYPE_INTRUSION_SET],
          ['campaigns', ENTITY_TYPE_CAMPAIGN],
          ['reports', ENTITY_TYPE_CONTAINER_REPORT],
        ])('should assign granted_refs for %s', (_, entityType) => {
          const context = createMockContext(false);
          const setting = createEntitySetting(entityType);
          const result = fillDefaultValues(context, mockUser, {}, setting);

          expectGrantedRefs(result, TEST_ORG_IDS);
        });
      });
    });

    describe('attributes configuration', () => {
      it('should assign granted_refs even with attributes_configuration', () => {
        const context = createMockContext(false);
        const setting = createEntitySetting(ENTITY_TYPE_MALWARE, '[]');
        const result = fillDefaultValues(context, mockUser, {}, setting);

        expectGrantedRefs(result, TEST_ORG_IDS);
      });
    });
  });
});
