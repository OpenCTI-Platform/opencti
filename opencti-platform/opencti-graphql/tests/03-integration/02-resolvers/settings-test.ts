import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { PLATFORM_VERSION } from '../../../src/config/conf';

const ABOUT_QUERY = gql`
  query About {
    about {
      version
      buildCommit
      memory {
        rss
        heapTotal
        heapUsed
        external
      }
      dependencies {
        name
        version
      }
      debugStats {
        objects {
          label
          value
        }
        relationships {
          label
          value
        }
      }
    }
  }
`;

const SETTINGS_QUERY = gql`
  query Settings {
    settings {
      id
      platform_title
      platform_type
      platform_ip_whitelist_enabled
      platform_session_idle_timeout
      platform_session_timeout
      platform_https_enabled
      caller_ip
      otp_mandatory
      password_policy_min_length
      password_policy_max_length
      password_policy_min_symbols
      password_policy_min_numbers
      password_policy_min_words
      password_policy_min_lowercase
      password_policy_min_uppercase
      password_policy_validity_days
      platform_notifier_auto_trigger_assignee
      platform_ai_enabled
      filigran_chatbot_ai_cgu_status
      is_authentication_by_env
    }
    publicSettings {
      id
      platform_title
      platform_providers {
        name
        type
        provider
      }
      platform_enterprise_edition_license_validated
      playground_enabled
      password_policy_min_length
      password_policy_max_length
      password_policy_min_symbols
      password_policy_min_numbers
      password_policy_min_words
      password_policy_min_lowercase
      password_policy_min_uppercase
      password_policy_validity_days
    }
  }
`;

const SETTINGS_CONTEXT_PATCH = gql`
  mutation SettingsContextPatch($id: ID!, $input: EditContext) {
    settingsEdit(id: $id) {
      contextPatch(input: $input) {
        id
        editContext {
          name
          focusOn
        }
      }
    }
  }
`;

const SETTINGS_CONTEXT_CLEAN = gql`
  mutation SettingsContextClean($id: ID!) {
    settingsEdit(id: $id) {
      contextClean {
        id
        editContext {
          name
          focusOn
        }
      }
    }
  }
`;

describe('Settings resolver', () => {
  it('should expose application information', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: ABOUT_QUERY });
    const about = data.about;

    expect(about?.version).toBe(PLATFORM_VERSION);
    expect(about?.buildCommit === null || /^[0-9a-f]{7}$/i.test(about?.buildCommit)).toBe(true);
    expect(about?.memory).toEqual(expect.objectContaining({
      rss: expect.any(Number),
      heapTotal: expect.any(Number),
      heapUsed: expect.any(Number),
      external: expect.any(Number),
    }));
    expect(about?.dependencies).toEqual([
      { name: 'Search engine', version: expect.any(String) },
      { name: 'RabbitMQ', version: expect.any(String) },
      { name: 'Redis', version: expect.any(String) },
      { name: 'XTM-One', version: expect.any(String) },
    ]);
    expect(about?.debugStats?.objects).toEqual(expect.any(Array));
    expect(about?.debugStats?.relationships).toEqual(expect.any(Array));
  });

  it('should expose authenticated and public settings consistently', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: SETTINGS_QUERY });
    const { settings, publicSettings } = data;

    expect(settings.id).toBe(publicSettings.id);
    expect(settings.platform_title).toBe(publicSettings.platform_title);
    expect(['LTS', 'STANDARD']).toContain(settings.platform_type);
    expect(settings.platform_ip_whitelist_enabled).toEqual(expect.any(Boolean));
    expect(settings.platform_session_idle_timeout).toEqual(expect.any(Number));
    expect(settings.platform_session_timeout).toEqual(expect.any(Number));
    expect(settings.platform_https_enabled).toEqual(expect.any(Boolean));
    expect(settings.caller_ip).toBeNull();
    expect(settings.otp_mandatory).toEqual(expect.any(Boolean));
    expect(settings.platform_notifier_auto_trigger_assignee).toEqual(expect.any(Boolean));
    expect(settings.platform_ai_enabled).toEqual(expect.any(Boolean));
    expect(['disabled', 'enabled', 'pending']).toContain(settings.filigran_chatbot_ai_cgu_status);
    expect(settings.is_authentication_by_env).toEqual(expect.any(Boolean));
    expect(publicSettings.platform_providers).toEqual(expect.any(Array));
    expect(publicSettings.platform_enterprise_edition_license_validated).toEqual(expect.any(Boolean));
    expect(publicSettings.playground_enabled).toEqual(expect.any(Boolean));

    const passwordPolicyFields = [
      'password_policy_min_length',
      'password_policy_max_length',
      'password_policy_min_symbols',
      'password_policy_min_numbers',
      'password_policy_min_words',
      'password_policy_min_lowercase',
      'password_policy_min_uppercase',
      'password_policy_validity_days',
    ];
    for (const field of passwordPolicyFields) {
      expect(settings[field]).toEqual(expect.any(Number));
      expect(publicSettings[field] === null || typeof publicSettings[field] === 'number').toBe(true);
      if (publicSettings[field] !== null) {
        expect(publicSettings[field]).toBe(settings[field]);
      }
    }
  });

  it('should patch and clean the settings edit context', async () => {
    const { data: settingsData } = await queryAsAdminWithSuccess({ query: SETTINGS_QUERY });
    const settingsId = settingsData.settings.id;

    try {
      const { data: patchData } = await queryAsAdminWithSuccess({
        query: SETTINGS_CONTEXT_PATCH,
        variables: { id: settingsId, input: { focusOn: 'platform_title' } },
      });
      const patchedSettings = patchData.settingsEdit.contextPatch;

      expect(patchedSettings.id).toBe(settingsId);
      expect(patchedSettings.editContext).toEqual(expect.arrayContaining([
        expect.objectContaining({ focusOn: 'platform_title' }),
      ]));
    } finally {
      const { data: cleanData } = await queryAsAdminWithSuccess({
        query: SETTINGS_CONTEXT_CLEAN,
        variables: { id: settingsId },
      });

      expect(cleanData.settingsEdit.contextClean.id).toBe(settingsId);
      expect(cleanData.settingsEdit.contextClean.editContext).toEqual([]);
    }
  });
});
