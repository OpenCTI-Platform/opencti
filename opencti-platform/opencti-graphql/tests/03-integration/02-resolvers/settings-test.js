import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { head } from 'ramda';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../src/schema/internalObject';
import { AI_DISABLED_ERROR_MESSAGE } from '../../../src/utils/ai/aiConstants';

const PLATFORM_AI_ENABLED_QUERY = gql`
  query settingsPlatformAiEnabled {
    settings {
      platform_ai_enabled
    }
  }
`;

const STIX_CORE_OBJECTS_QUERY = gql`
  query stixCoreObjects($first: Int!) {
    stixCoreObjects(first: $first) {
      edges {
        node {
          id
        }
      }
    }
  }
`;

const getAnyStixCoreObjectId = async () => {
  const result = await queryAsAdmin({ query: STIX_CORE_OBJECTS_QUERY, variables: { first: 1 } });
  return result?.data?.stixCoreObjects?.edges?.at(0)?.node?.id;
};

const waitForPlatformAiEnabled = async (expectedEnabled) => {
  const WAIT_FOR_SETTINGS_TIMEOUT_MS = Number(process.env.WAIT_FOR_SETTINGS_TIMEOUT_MS) || 10000;
  const WAIT_FOR_SETTINGS_INTERVAL_MS = Number(process.env.WAIT_FOR_SETTINGS_INTERVAL_MS) || 250;
  const deadline = Date.now() + WAIT_FOR_SETTINGS_TIMEOUT_MS;
  let lastValue;

  // Poll directly so we fully control timeout detection. Genuine query errors
  // (GraphQL/network) propagate as-is and are never masked as a timeout, while
  // an actual timeout throws a dedicated message that includes lastValue.
  do {
    const settingsResult = await queryAsAdmin({ query: PLATFORM_AI_ENABLED_QUERY, variables: {} });
    lastValue = settingsResult?.data?.settings?.platform_ai_enabled;
    if (lastValue === expectedEnabled) {
      return;
    }
    await new Promise((resolve) => { setTimeout(resolve, WAIT_FOR_SETTINGS_INTERVAL_MS); });
  } while (Date.now() < deadline);

  throw new Error(
    `Timed out waiting for settings.platform_ai_enabled to become ${expectedEnabled} (last observed: ${lastValue})`,
  );
};

const UPDATE_SETTINGS_QUERY = gql`
  mutation SettingsEdit($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        platform_ai_enabled
      }
    }
  }
`;

const AI_FIX_SPELLING_MUTATION = gql`
  mutation AiFixSpelling($id: ID!, $content: String!) {
    aiFixSpelling(id: $id, content: $content)
  }
`;

const AI_ACTIVITY_QUERY = gql`
  query StixCoreObjectAskAiActivity($id: ID!) {
    stixCoreObjectAskAiActivity(id: $id) {
      result
      trend
      updated_at
    }
  }
`;

const ENTERPRISE_EDITION_QUERY = gql`
  query settingsEnterpriseEdition {
    settings {
      platform_enterprise_edition {
        license_validated
      }
    }
  }
`;

const isEnterpriseEditionEnabled = async () => {
  const result = await queryAsAdmin({ query: ENTERPRISE_EDITION_QUERY, variables: {} });
  return result?.data?.settings?.platform_enterprise_edition?.license_validated === true;
};

const ABOUT_QUERY = gql`
  query about {
    about {
      version
      dependencies {
        name
        version
      }
    }
  }
`;

const READ_QUERY = gql`
  query settings {
    settings {
      id
      platform_ai_enabled
      platform_title
      platform_email
      platform_language
      platform_ip_whitelist_enabled
      caller_ip
      platform_ip_whitelist_exclusions {
        id
      }
      platform_theme {
        name
      }
      platform_providers {
        name
        provider
        type
      }
      editContext {
        name
        focusOn
      }
    }
  }
`;

describe('Settings resolver standard behavior', () => {
  const PLATFORM_TITLE = 'OpenCTI - Cyber Threat Intelligence Platform';
  const settingsId = async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: {} });
    const { settings } = queryResult.data;
    return settings.id;
  };
  it('should about information', async () => {
    const queryResult = await queryAsAdmin({ query: ABOUT_QUERY, variables: {} });
    expect(queryResult).not.toBeNull();
    const { about } = queryResult.data;
    expect(about).not.toBeNull();
    expect(about.dependencies.length).toEqual(4);
  });
  it('should settings information', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: {} });
    expect(queryResult).not.toBeNull();
    const { settings } = queryResult.data;
    expect(settings).not.toBeNull();
    expect(settings.platform_title).toEqual(PLATFORM_TITLE);
    expect(settings.platform_email).toEqual('admin@opencti.io');
    expect(settings.platform_language).toEqual('auto');
    expect(settings.platform_ip_whitelist_enabled).toBeDefined();
    expect(settings.caller_ip).toBeDefined();
    expect(settings.platform_ip_whitelist_exclusions).toBeDefined();
    expect(settings.platform_theme.name).toEqual('Dark');
    expect(settings.editContext.length).toEqual(0);
  });
  it('should update settings', async () => {
    const UPDATE_QUERY = gql`
      mutation SettingsEdit($id: ID!, $input: [EditInput]!) {
        settingsEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            platform_title
          }
        }
      }
    `;
    const settingsInternalId = await settingsId();
    let queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: settingsInternalId, input: { key: 'platform_title', value: ['Cyber'] } },
    });
    expect(queryResult.data.settingsEdit.fieldPatch.platform_title).toEqual('Cyber');
    // Back to previous value
    queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: settingsInternalId,
        input: { key: 'platform_title', value: [PLATFORM_TITLE] },
      },
    });
    expect(queryResult.data.settingsEdit.fieldPatch.platform_title).toEqual(PLATFORM_TITLE);
  });
  it('should fail when updating filigran_chatbot_ai_cgu_status with an invalid value', async () => {
    const UPDATE_QUERY = gql`
      mutation SettingsEdit($id: ID!, $input: [EditInput]!) {
        settingsEdit(id: $id) {
          fieldPatch(input: $input) {
            id
          }
        }
      }
    `;
    const settingsInternalId = await settingsId();
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: {
        id: settingsInternalId,
        input: { key: 'filigran_chatbot_ai_cgu_status', value: ['INVALID_STATUS'] },
      },
    });
    expect(queryResult.errors).toBeDefined();
    expect(queryResult.errors.length).toEqual(1);
    expect(queryResult.errors[0].message).toContain('Invalid CGU status');
  });
  it('should context patch settings', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation SettingsEdit($id: ID!, $input: EditContext) {
        settingsEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const settingsInternalId = await settingsId();
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: settingsInternalId, input: { focusOn: 'platform_title' } },
    });
    expect(queryResult.data.settingsEdit.contextPatch.id).toEqual(settingsInternalId);
    const readResult = await queryAsAdmin({ query: READ_QUERY, variables: {} });
    const { editContext } = readResult.data.settings;
    expect(editContext.length).toEqual(1);
    expect(head(editContext).focusOn).toEqual('platform_title');
  });
  it('should context clean settings', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation SettingsEdit($id: ID!) {
        settingsEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const settingsInternalId = await settingsId();
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: settingsInternalId },
    });
    expect(queryResult.data.settingsEdit.contextClean.id).toEqual(settingsInternalId);
    const readResult = await queryAsAdmin({ query: READ_QUERY, variables: {} });
    const { editContext } = readResult.data.settings;
    expect(editContext.length).toEqual(0);
  });

  it('should block AI operations when platform AI is disabled', async function () {
    const settingsInternalId = await settingsId();
    const initialSettingsResult = await queryAsAdmin({ query: READ_QUERY, variables: {} });
    const platformAiEnabled = initialSettingsResult.data.settings.platform_ai_enabled;
    const initialAiEnabled = platformAiEnabled;

    // If Enterprise edition is not enabled, AI mutations are not available.
    // Detect EE via a stable settings field instead of probing an AI resolver
    // (which could trigger a real AI call and make the test slow/flaky), and
    // skip the test cleanly before mutating settings in that case.
    if (!(await isEnterpriseEditionEnabled())) {
      this.skip();
    }

    if (!initialAiEnabled) {
      await queryAsAdmin({
        query: UPDATE_SETTINGS_QUERY,
        variables: { id: settingsInternalId, input: [{ key: 'platform_ai_enabled', value: [true] }] },
      });
      resetCacheForEntity(ENTITY_TYPE_SETTINGS);
      await waitForPlatformAiEnabled(true);
    }

    try {
      await queryAsAdmin({
        query: UPDATE_SETTINGS_QUERY,
        variables: { id: settingsInternalId, input: [{ key: 'platform_ai_enabled', value: [false] }] },
      });
      resetCacheForEntity(ENTITY_TYPE_SETTINGS);

      await waitForPlatformAiEnabled(false);

      const stixCoreObjectId = await getAnyStixCoreObjectId();
      expect(stixCoreObjectId).toBeDefined();

      const aiResult = await queryAsAdmin({
        query: AI_FIX_SPELLING_MUTATION,
        variables: { id: 'ai-test', content: 'Some content to check.' },
      });
      expect(aiResult).not.toBeNull();
      expect(aiResult.errors).toBeDefined();
      expect(aiResult.errors.length).toEqual(1);
      const errorMessage = aiResult.errors.at(0).message;
      expect(errorMessage).toBe(AI_DISABLED_ERROR_MESSAGE);

      const aiActivityResult = await queryAsAdmin({
        query: AI_ACTIVITY_QUERY,
        variables: { id: stixCoreObjectId },
      });
      expect(aiActivityResult).not.toBeNull();
      expect(aiActivityResult.errors).toBeDefined();
      expect(aiActivityResult.errors.length).toEqual(1);
      const activityErrorMessage = aiActivityResult.errors.at(0).message;
      expect(activityErrorMessage).toBe(AI_DISABLED_ERROR_MESSAGE);
    } finally {
      try {
        await queryAsAdmin({
          query: UPDATE_SETTINGS_QUERY,
          variables: { id: settingsInternalId, input: [{ key: 'platform_ai_enabled', value: [initialAiEnabled] }] },
        });
        resetCacheForEntity(ENTITY_TYPE_SETTINGS);

        await waitForPlatformAiEnabled(initialAiEnabled);
      } catch (cleanupError) {
        // Best-effort cleanup: do not mask the original test failure
        // but log the cleanup error to aid debugging.
        // eslint-disable-next-line no-console
        console.error('Failed to restore initial platform_ai_enabled setting after test:', cleanupError);
      }
    }
  });
});

const READ_MESSAGES_QUERY = gql`
  query settingsMessages {
    settings {
      id
      platform_messages {
        id
        message
        activated
        dismissible
        updated_at
      }
    }
  }
`;

const EDIT_MESSAGES_QUERY = gql`
  mutation editMessages($id: ID!, $input: SettingsMessageInput!) {
    settingsEdit(id: $id) {
      editMessage(input: $input) {
        platform_messages {
          id
          message
          activated
          dismissible
          updated_at
        }
      }
    }
  }
`;

const REMOVE_MESSAGE_QUERY = gql`
  mutation deleteMessage($id: ID!, $input: String!) {
    settingsEdit(id: $id) {
      deleteMessage(input: $input) {
        platform_messages {
          id
          message
          activated
          dismissible
          updated_at
        }
      }
    }
  }
`;

describe('Settings resolver messages behavior', () => {
  it('should edit messages', async () => {
    // -- PREPARE -
    let queryResult = await queryAsAdmin({ query: READ_MESSAGES_QUERY, variables: {} });
    expect(queryResult).not.toBeNull();
    const { settings } = queryResult.data;
    const newMessage = 'This OpenCTI instance will be inaccessible for one hour.';
    let message = { message: newMessage, activated: false, dismissible: false };

    // -- EXECUTE --
    queryResult = await queryAsAdmin({ query: EDIT_MESSAGES_QUERY, variables: { id: settings.id, input: message } });
    expect(queryResult).not.toBeNull();

    // -- ASSERT --
    const { platform_messages } = queryResult.data.settingsEdit.editMessage;
    expect(platform_messages.length).toEqual(1);
    [message] = platform_messages;
    expect(message.message).toEqual(newMessage);
  });
  it('should delete messages', async () => {
    // -- PREPARE -
    let queryResult = await queryAsAdmin({ query: READ_MESSAGES_QUERY, variables: {} });
    expect(queryResult).not.toBeNull();
    const { settings } = queryResult.data;
    const [message] = settings.platform_messages;
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);

    // -- EXECUTE --
    queryResult = await queryAsAdmin({ query: REMOVE_MESSAGE_QUERY, variables: { id: settings.id, input: message.id } });
    expect(queryResult).not.toBeNull();

    // -- ASSERT --
    const { platform_messages } = queryResult.data.settingsEdit.deleteMessage;
    expect(platform_messages.length).toEqual(0);
  });
});
