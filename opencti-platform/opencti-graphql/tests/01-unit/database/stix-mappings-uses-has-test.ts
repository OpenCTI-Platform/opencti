import { describe, expect, it } from 'vitest';
import { checkStixCoreRelationshipMapping } from '../../../src/database/stix';
import { ENTITY_TYPE_IDENTITY_SYSTEM, ENTITY_TYPE_VULNERABILITY } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { ENTITY_SOFTWARE } from '../../../src/schema/stixCyberObservable';
import { RELATION_USES, RELATION_HAS } from '../../../src/schema/stixCoreRelationship';

/**
 * Unit tests to validate the new relationship mappings in the STIX model:
 * 1. System → uses → Software
 * 2. Organization → has → Vulnerability
 */
describe('Relationship Mappings Validation', () => {
  describe('System → uses → Software', () => {
    it('should allow System to use Software relationship', () => {
      const isValid = checkStixCoreRelationshipMapping(
        ENTITY_TYPE_IDENTITY_SYSTEM,
        ENTITY_SOFTWARE,
        RELATION_USES,
      );
      expect(isValid).toBe(true);
    });

    it('should not allow reverse Software to System relationship with uses', () => {
      const isValid = checkStixCoreRelationshipMapping(
        ENTITY_SOFTWARE,
        ENTITY_TYPE_IDENTITY_SYSTEM,
        RELATION_USES,
      );
      expect(isValid).toBe(false);
    });
  });

  describe('Organization → has → Vulnerability', () => {
    it('should allow Organization to have Vulnerability relationship', () => {
      const isValid = checkStixCoreRelationshipMapping(
        ENTITY_TYPE_IDENTITY_ORGANIZATION,
        ENTITY_TYPE_VULNERABILITY,
        RELATION_HAS,
      );
      expect(isValid).toBe(true);
    });

    it('should not allow reverse Vulnerability to Organization relationship with has', () => {
      const isValid = checkStixCoreRelationshipMapping(
        ENTITY_TYPE_VULNERABILITY,
        ENTITY_TYPE_IDENTITY_ORGANIZATION,
        RELATION_HAS,
      );
      expect(isValid).toBe(false);
    });
  });

  describe('Complete Vulnerability Impact Chain', () => {
    it('should validate complete chain: Vulnerability → Software → System → Organization', () => {
      // Vulnerability → Software (already exists: has)
      const vulnToSoftware = checkStixCoreRelationshipMapping(
        ENTITY_SOFTWARE,
        ENTITY_TYPE_VULNERABILITY,
        RELATION_HAS,
      );

      // Software → System (new: uses - bidirectional, so System → uses → Software)
      const systemToSoftware = checkStixCoreRelationshipMapping(
        ENTITY_TYPE_IDENTITY_SYSTEM,
        ENTITY_SOFTWARE,
        RELATION_USES,
      );

      // Organization → Vulnerability (new: has)
      const orgToVuln = checkStixCoreRelationshipMapping(
        ENTITY_TYPE_IDENTITY_ORGANIZATION,
        ENTITY_TYPE_VULNERABILITY,
        RELATION_HAS,
      );

      expect(vulnToSoftware).toBe(true);
      expect(systemToSoftware).toBe(true);
      expect(orgToVuln).toBe(true);
    });
  });
});
