import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { print } from 'graphql';
import gql from 'graphql-tag';
import { ADMIN_USER, queryInitPlatformAsAdmin, queryInitPlatformAsUser, queryInitPlatformAsAnonymous, USER_EDITOR, testContext, getGroupIdByName } from '../utils/testQuery';
import { getSettings, settingsEditField } from '../../src/domain/settings';
import { resetCacheForEntity } from '../../src/database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../src/schema/internalObject';

// ─── GraphQL Queries ─────────────────────────────────────────────────────────

const ME_QUERY = print(gql`
  query MeQuery {
    me {
      id
      name
      user_email
    }
  }
`);

const PUBLIC_SETTINGS_QUERY = print(gql`
  query publicSettings {
    publicSettings {
      platform_title
    }
  }
`);

// ─── Helpers ─────────────────────────────────────────────────────────────────

let settingsId: string;

const enableWhitelist = async (ips: string[], exclusionIds: string[] = []) => {
  const input = [
    { key: 'platform_ip_whitelist_enabled', value: ['true'] },
    { key: 'platform_ip_whitelist', value: ips },
    { key: 'platform_ip_whitelist_exclusion_ids', value: exclusionIds },
  ];
  await settingsEditField(testContext, ADMIN_USER, settingsId, input);
  resetCacheForEntity(ENTITY_TYPE_SETTINGS);
};

const disableWhitelist = async () => {
  const input = [
    { key: 'platform_ip_whitelist_enabled', value: ['false'] },
    { key: 'platform_ip_whitelist', value: [] },
    { key: 'platform_ip_whitelist_exclusion_ids', value: [] },
  ];
  await settingsEditField(testContext, ADMIN_USER, settingsId, input);
  resetCacheForEntity(ENTITY_TYPE_SETTINGS);
};

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('IP Whitelist Middleware Integration', () => {
  beforeAll(async () => {
    const settings: any = await getSettings(testContext);
    settingsId = settings.id;
  });

  afterAll(async () => {
    await disableWhitelist();
  });

  describe('Feature activation and default behavior', () => {
    afterAll(async () => {
      await disableWhitelist();
    });

    it('should allow access when whitelist is disabled', async () => {
      await disableWhitelist();
      const result = await queryInitPlatformAsAdmin(ME_QUERY);
      expect(result.data.me).toBeDefined();
      expect(result.data.me.user_email).toBe('admin@opencti.io');
    });

    it('should allow access when whitelist is enabled but IP matches (localhost)', async () => {
      await enableWhitelist(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
      const result = await queryInitPlatformAsAdmin(ME_QUERY);
      expect(result.data.me).toBeDefined();
      expect(result.data.me.user_email).toBe('admin@opencti.io');
    });

    it('should allow access when whitelist includes a CIDR that covers localhost', async () => {
      await enableWhitelist(['127.0.0.0/8', '::1/128']);
      const result = await queryInitPlatformAsAdmin(ME_QUERY);
      expect(result.data.me).toBeDefined();
    });
  });

  describe('Blocking non-whitelisted IPs', () => {
    afterAll(async () => {
      await disableWhitelist();
    });

    it('should block authenticated user when IP is not in whitelist', async () => {
      await enableWhitelist(['10.99.99.99']);
      const result = await queryInitPlatformAsAdmin(ME_QUERY);
      expect(result.errors).toBeDefined();
      expect(result.errors.length).toBe(1);
      expect(result.errors[0].extensions.code).toBe('IP_FORBIDDEN');
    });

    it('should block non-admin user when IP is not in whitelist', async () => {
      await enableWhitelist(['10.99.99.99']);
      const result = await queryInitPlatformAsUser(USER_EDITOR, ME_QUERY);
      expect(result.errors).toBeDefined();
      expect(result.errors[0].extensions.code).toBe('IP_FORBIDDEN');
    });
  });

  describe('Login operations bypass for unauthenticated users', () => {
    afterAll(async () => {
      await disableWhitelist();
    });

    it('should allow publicSettings query for unauthenticated users even when IP is not whitelisted', async () => {
      await enableWhitelist(['10.99.99.99']);
      // publicSettings is a recognized login operation — parsed from the query document
      const result = await queryInitPlatformAsAnonymous(PUBLIC_SETTINGS_QUERY);
      expect(result.data?.publicSettings).toBeDefined();
    });

    it('should block non-login operations for unauthenticated users when IP is not whitelisted', async () => {
      await enableWhitelist(['10.99.99.99']);
      const result = await queryInitPlatformAsAnonymous(ME_QUERY);
      expect(result.errors).toBeDefined();
      expect(result.errors[0].extensions.code).toBe('IP_FORBIDDEN');
    });
  });

  describe('Exclusion list bypass', () => {
    afterAll(async () => {
      await disableWhitelist();
    });

    it('should allow excluded user to access even when IP is not in whitelist', async () => {
      await enableWhitelist(['10.99.99.99'], [ADMIN_USER.id]);
      const result = await queryInitPlatformAsAdmin(ME_QUERY);
      expect(result.data?.me).toBeDefined();
      expect(result.data.me.user_email).toBe('admin@opencti.io');
    });

    it('should still block non-excluded users', async () => {
      await enableWhitelist(['10.99.99.99'], [ADMIN_USER.id]);
      const result = await queryInitPlatformAsUser(USER_EDITOR, ME_QUERY);
      expect(result.errors).toBeDefined();
      expect(result.errors[0].extensions.code).toBe('IP_FORBIDDEN');
    });

    it('should allow excluded user via group membership', async () => {
      const amberGroupId = await getGroupIdByName(USER_EDITOR.groups[0].name);
      await enableWhitelist(['10.99.99.99'], [amberGroupId]);
      const result = await queryInitPlatformAsUser(USER_EDITOR, ME_QUERY);
      expect(result.data?.me).toBeDefined();
      expect(result.data.me.user_email).toBe('editor@opencti.io');
    });
  });

  describe('Empty whitelist behavior', () => {
    afterAll(async () => {
      await disableWhitelist();
    });

    it('should allow access when whitelist is enabled but IP list is empty', async () => {
      const input = [
        { key: 'platform_ip_whitelist_enabled', value: ['true'] },
        { key: 'platform_ip_whitelist', value: [] },
      ];
      await settingsEditField(testContext, ADMIN_USER, settingsId, input);
      resetCacheForEntity(ENTITY_TYPE_SETTINGS);
      const result = await queryInitPlatformAsAdmin(ME_QUERY);
      expect(result.data?.me).toBeDefined();
    });
  });

  describe('Re-enabling access after disabling whitelist', () => {
    it('should restore access after whitelist is disabled', async () => {
      await enableWhitelist(['10.99.99.99']);
      const blockedResult = await queryInitPlatformAsAdmin(ME_QUERY);
      expect(blockedResult.errors).toBeDefined();
      expect(blockedResult.errors[0].extensions.code).toBe('IP_FORBIDDEN');

      await disableWhitelist();
      const allowedResult = await queryInitPlatformAsAdmin(ME_QUERY);
      expect(allowedResult.data?.me).toBeDefined();
      expect(allowedResult.data.me.user_email).toBe('admin@opencti.io');
    });
  });
});
