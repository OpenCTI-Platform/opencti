import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { head } from 'ramda';
import { queryAsAdmin, createUploadFromTestDataFile } from '../../utils/testQueryHelper';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../src/schema/internalObject';
import { downloadFileRange } from '../../../src/database/raw-file-storage';

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
      password_policy_validity_days
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
    expect(settings.password_policy_validity_days).toBeDefined();
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

describe('Settings map tile management', () => {
  const MAP_TILE_SETTINGS_QUERY = gql`
    query settings {
      settings {
        id
        platform_map_tile_server_mode
        platform_map_tile_server_s3_file {
          name
          size
          sha256
        }
      }
    }
  `;

  const MAP_TILE_MODE_UPDATE = gql`
    mutation SettingsEdit($id: ID!, $input: [EditInput]!) {
      settingsEdit(id: $id) {
        fieldPatch(input: $input) {
          id
          platform_map_tile_server_mode
        }
      }
    }
  `;

  const MAP_TILE_UPLOAD = gql`
    mutation SettingsMapTileUpload($id: ID!, $file: Upload!) {
      settingsEdit(id: $id) {
        uploadMapTileData(file: $file) {
          id
          platform_map_tile_server_s3_file {
            name
            size
            sha256
          }
        }
      }
    }
  `;

  const MAP_TILE_DELETE = gql`
    mutation SettingsMapTileDelete($id: ID!) {
      settingsEdit(id: $id) {
        deleteMapTileData {
          id
          platform_map_tile_server_s3_file {
            name
            size
            sha256
          }
        }
      }
    }
  `;

  const settingsId = async () => {
    const queryResult = await queryAsAdmin({ query: MAP_TILE_SETTINGS_QUERY });
    return queryResult.data.settings.id;
  };

  it('should default to bundled mode', async () => {
    const queryResult = await queryAsAdmin({ query: MAP_TILE_SETTINGS_QUERY });
    expect(queryResult.data.settings.platform_map_tile_server_mode).toEqual('bundled');
  });

  it('should have no S3 file initially', async () => {
    const queryResult = await queryAsAdmin({ query: MAP_TILE_SETTINGS_QUERY });
    expect(queryResult.data.settings.platform_map_tile_server_s3_file).toBeNull();
  });

  it('should upload a PMTiles file to S3', async () => {
    const id = await settingsId();
    const upload = await createUploadFromTestDataFile('test-map-tiles.pmtiles', 'test-map-tiles.pmtiles', 'application/octet-stream');
    const queryResult = await queryAsAdmin({
      query: MAP_TILE_UPLOAD,
      variables: { id, file: upload },
    });
    expect(queryResult.errors).toBeUndefined();
    const s3File = queryResult.data.settingsEdit.uploadMapTileData.platform_map_tile_server_s3_file;
    expect(s3File).not.toBeNull();
    expect(s3File.name).toEqual('test-map-tiles.pmtiles');
    expect(s3File.size).toBeGreaterThan(0);
    expect(s3File.sha256).toBeDefined();
    expect(s3File.sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it('should download full file via downloadFileRange without range', async () => {
    const result = await downloadFileRange('maps/world.pmtiles');
    expect(result).not.toBeNull();
    expect(result.totalSize).toBeGreaterThan(0);
    expect(result.contentLength).toEqual(result.totalSize);
    expect(result.contentRange).toBeUndefined();
    expect(result.etag).toBeDefined();
    result.stream.destroy();
  });

  it('should download partial content via downloadFileRange with range', async () => {
    const result = await downloadFileRange('maps/world.pmtiles', 'bytes=0-9');
    expect(result).not.toBeNull();
    expect(result.contentLength).toEqual(10);
    expect(result.contentRange).toMatch(/^bytes 0-9\//);
    expect(result.totalSize).toBeGreaterThan(10);
    expect(result.etag).toBeDefined();
    result.stream.destroy();
  });

  it('should return null from downloadFileRange for non-existent key', async () => {
    const result = await downloadFileRange('maps/non-existent.pmtiles');
    expect(result).toBeNull();
  });

  it('should switch mode to s3', async () => {
    const id = await settingsId();
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    const queryResult = await queryAsAdmin({
      query: MAP_TILE_MODE_UPDATE,
      variables: { id, input: { key: 'platform_map_tile_server_mode', value: ['s3'] } },
    });
    expect(queryResult.errors).toBeUndefined();
    expect(queryResult.data.settingsEdit.fieldPatch.platform_map_tile_server_mode).toEqual('s3');
  });

  it('should switch mode back to bundled', async () => {
    const id = await settingsId();
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    const queryResult = await queryAsAdmin({
      query: MAP_TILE_MODE_UPDATE,
      variables: { id, input: { key: 'platform_map_tile_server_mode', value: ['bundled'] } },
    });
    expect(queryResult.errors).toBeUndefined();
    expect(queryResult.data.settingsEdit.fieldPatch.platform_map_tile_server_mode).toEqual('bundled');
  });

  it('should delete the S3 PMTiles file', async () => {
    const id = await settingsId();
    const queryResult = await queryAsAdmin({
      query: MAP_TILE_DELETE,
      variables: { id },
    });
    expect(queryResult.errors).toBeUndefined();
    expect(queryResult.data.settingsEdit.deleteMapTileData.platform_map_tile_server_s3_file).toBeNull();
  });

  it('should have no S3 file after deletion', async () => {
    const queryResult = await queryAsAdmin({ query: MAP_TILE_SETTINGS_QUERY });
    expect(queryResult.data.settings.platform_map_tile_server_s3_file).toBeNull();
  });
});
