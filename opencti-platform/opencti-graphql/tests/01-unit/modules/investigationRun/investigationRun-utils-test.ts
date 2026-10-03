import { describe, expect, it } from 'vitest';
import { intersectOrganizationIds, isCreationSharingWidened } from '../../../../src/modules/investigationRun/investigationRun-utils';
import { RELATION_GRANTED_TO } from '../../../../src/schema/stixRefRelationship';
import { ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../../src/schema/stixMetaObject';
import { KNOWLEDGE_ORGANIZATION_RESTRICT } from '../../../../src/utils/access';
import type { AuthUser } from '../../../../src/types/user';
import type { BasicStoreSettings } from '../../../../src/types/settings';

const sharedWith = (entityType: string, organizations: string[]) => ({ entity_type: entityType, [RELATION_GRANTED_TO]: organizations });
const userOf = (organizations: string[], capabilities: string[] = []) => ({
  id: 'user',
  organizations: organizations.map((id) => ({ internal_id: id })),
  capabilities: capabilities.map((name) => ({ name })),
  user_service_account: false,
} as unknown as AuthUser);
const withPlatformOrganization = { platform_organization: 'platform-org' } as unknown as BasicStoreSettings;
const withoutPlatformOrganization = {} as unknown as BasicStoreSettings;

describe('Case Autopilot restrictive organization sharing', () => {
  it('narrows the sharing to the organizations every cited object is shared with', () => {
    const cited = [sharedWith(ENTITY_TYPE_MALWARE, ['org-a', 'org-b']), sharedWith(ENTITY_TYPE_INTRUSION_SET, ['org-b', 'org-c'])];
    expect(intersectOrganizationIds(['org-a', 'org-b', 'org-c'], cited)).toEqual(['org-b']);
  });

  it('keeps the platform organization only when the citations share no organization', () => {
    expect(intersectOrganizationIds(['org-a'], [sharedWith(ENTITY_TYPE_MALWARE, ['org-b'])])).toEqual([]);
    expect(intersectOrganizationIds(['org-a'], [sharedWith(ENTITY_TYPE_MALWARE, [])])).toEqual([]);
  });

  it('ignores objects visible whatever the organization', () => {
    expect(intersectOrganizationIds(['org-a'], [sharedWith(ENTITY_TYPE_MARKING_DEFINITION, [])])).toEqual(['org-a']);
  });

  it('detects an identity that would share outputs beyond the organizations of the evidence', () => {
    // Outside the platform organization, without the restriction capability: its own organizations apply.
    expect(isCreationSharingWidened(userOf(['org-a', 'org-b']), withPlatformOrganization, false, ['org-b'])).toBe(true);
    expect(isCreationSharingWidened(userOf(['org-b']), withPlatformOrganization, false, ['org-b', 'org-c'])).toBe(false);
    // The requested organizations apply when the identity may restrict.
    expect(isCreationSharingWidened(userOf(['org-a', 'org-b'], [KNOWLEDGE_ORGANIZATION_RESTRICT]), withPlatformOrganization, false, ['org-b'])).toBe(false);
    // Inside the platform organization, nothing is shared beyond it.
    expect(isCreationSharingWidened(userOf(['org-a']), withPlatformOrganization, true, [])).toBe(false);
    // Without a platform organization there is no organization segregation.
    expect(isCreationSharingWidened(userOf(['org-a']), withoutPlatformOrganization, false, [])).toBe(false);
  });
});
