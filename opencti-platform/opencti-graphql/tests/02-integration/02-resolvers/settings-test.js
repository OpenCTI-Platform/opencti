import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { head } from 'ramda';
import { queryAsAdmin } from '../../utils/testQuery';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../src/schema/internalObject';

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
      platform_title
      platform_email
      platform_language
      platform_theme
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
    expect(about.dependencies.length).toEqual(3);
  });
  it('should settings information', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: {} });
    expect(queryResult).not.toBeNull();
    const { settings } = queryResult.data;
    expect(settings).not.toBeNull();
    expect(settings.platform_title).toEqual(PLATFORM_TITLE);
    expect(settings.platform_email).toEqual('admin@opencti.io');
    expect(settings.platform_language).toEqual('auto');
    expect(settings.platform_theme).toEqual('Dark');
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
