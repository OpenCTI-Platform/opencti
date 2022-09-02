import gql from 'graphql-tag';
import { head } from 'ramda';
import { queryAsAdmin } from '../../utils/testQuery';

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
  const PLATFORM_TITLE = 'Cyber threat intelligence platform';
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
    expect(settings.platform_theme).toEqual('dark');
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
