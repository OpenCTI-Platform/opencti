import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { gunzipSync } from 'node:zlib';
import gql from 'graphql-tag';
import { head } from 'ramda';
import { createUploadFromTestDataFile, queryAsAdmin, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../src/schema/internalObject';
import { downloadFile, downloadFileRange } from '../../../src/database/raw-file-storage';
import { USER_EDITOR, USER_SECURITY } from '../../utils/testQuery';

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

const EDIT_FIELD_QUERY = gql`
  mutation SettingsEdit($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        platform_title
        local_auth {
            enabled
          }
      }
    }
  }
`;

const CONTEXT_PATCH_QUERY = gql`
  mutation SettingsEdit($id: ID!, $input: EditContext) {
    settingsEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const CONTEXT_CLEAN_QUERY = gql`
  mutation SettingsEdit($id: ID!) {
    settingsEdit(id: $id) {
      contextClean {
        id
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
    expect(settings.platform_theme.name).toEqual('Filigran Dark');
    expect(settings.password_policy_validity_days).toBeDefined();
    expect(settings.editContext.length).toEqual(0);
  });
  it('should update settings', async () => {
    const settingsInternalId = await settingsId();
    let queryResult = await queryAsAdmin({
      query: EDIT_FIELD_QUERY,
      variables: { id: settingsInternalId, input: { key: 'platform_title', value: ['Cyber'] } },
    });
    expect(queryResult.data.settingsEdit.fieldPatch.platform_title).toEqual('Cyber');
    // Back to previous value
    queryResult = await queryAsAdmin({
      query: EDIT_FIELD_QUERY,
      variables: {
        id: settingsInternalId,
        input: { key: 'platform_title', value: [PLATFORM_TITLE] },
      },
    });
    expect(queryResult.data.settingsEdit.fieldPatch.platform_title).toEqual(PLATFORM_TITLE);
  });
  it('should fail when updating filigran_chatbot_ai_cgu_status with an invalid value', async () => {
    const settingsInternalId = await settingsId();
    const queryResult = await queryAsAdmin({
      query: EDIT_FIELD_QUERY,
      variables: {
        id: settingsInternalId,
        input: { key: 'filigran_chatbot_ai_cgu_status', value: ['INVALID_STATUS'] },
      },
    });
    expect(queryResult.errors).toBeDefined();
    expect(queryResult.errors.length).toEqual(1);
    expect(queryResult.errors[0].message).toContain('Invalid CGU status');
  });
  it('should reject fieldPatch when key requires missing capability', async () => {
    const settingsInternalId = await settingsId();
    await queryAsUserIsExpectedForbidden(USER_SECURITY, {
      query: EDIT_FIELD_QUERY,
      variables: { id: settingsInternalId, input: { key: 'platform_title', value: ['forbidden-update'] } },
    });
  });
  it('should allow updating local_auth with SETTINGS_SETAUTH capability', async () => {
    const settingsInternalId = await settingsId();

    await queryAsUserWithSuccess(USER_SECURITY, {
      query: EDIT_FIELD_QUERY,
      variables: { id: settingsInternalId, input: { key: 'local_auth', value: [{ enabled: true }] } },
    });

    // Restore default test value.
    await queryAsAdmin({
      query: EDIT_FIELD_QUERY,
      variables: { id: settingsInternalId, input: { key: 'local_auth', value: [{ enabled: true }] } },
    });
  });
  it('should reject updating local_auth without SETTINGS_SETAUTH capability', async () => {
    const settingsInternalId = await settingsId();
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: EDIT_FIELD_QUERY,
      variables: { id: settingsInternalId, input: { key: 'local_auth', value: [{ enabled: true }] } },
    });
  });
  it('should context patch settings', async () => {
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
    const settingsInternalId = await settingsId();
    const queryResult = await queryAsAdmin({
      query: CONTEXT_CLEAN_QUERY,
      variables: { id: settingsInternalId },
    });
    expect(queryResult.data.settingsEdit.contextClean.id).toEqual(settingsInternalId);
    const readResult = await queryAsAdmin({ query: READ_QUERY, variables: {} });
    const { editContext } = readResult.data.settings;
    expect(editContext.length).toEqual(0);
  });
});

const READ_LOCKOUT_QUERY = gql`
  query settingsLockout {
    settings {
      id
      local_auth_lockout_enabled
      local_auth_lockout_max_attempts
      local_auth_lockout_window
      local_auth_lockout_duration
      local_auth_lockout_max_duration
    }
  }
`;

const UPDATE_LOCAL_AUTH_QUERY = gql`
  mutation updateLocalAuth($id: ID!, $input: LocalAuthConfigInput!) {
    settingsEdit(id: $id) {
      updateLocalAuth(input: $input) {
        id
        local_auth {
          enabled
        }
        local_auth_lockout_enabled
        local_auth_lockout_max_attempts
        local_auth_lockout_window
        local_auth_lockout_duration
        local_auth_lockout_max_duration
      }
    }
  }
`;

describe('Settings resolver local authentication lockout policy', () => {
  // A null value removes the stored value, so the default is returned again
  const RESET_LOCKOUT_INPUT = {
    enabled: true,
    local_auth_lockout_enabled: null,
    local_auth_lockout_max_attempts: null,
    local_auth_lockout_window: null,
    local_auth_lockout_duration: null,
    local_auth_lockout_max_duration: null,
  };
  let settingsInternalId;
  beforeAll(async () => {
    const queryResult = await queryAsAdmin({ query: READ_LOCKOUT_QUERY, variables: {} });
    settingsInternalId = queryResult.data.settings.id;
    await queryAsAdmin({ query: UPDATE_LOCAL_AUTH_QUERY, variables: { id: settingsInternalId, input: RESET_LOCKOUT_INPUT } });
  });
  beforeEach(() => {
    // Validation reads the current policy from the settings cache
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
  });
  afterAll(async () => {
    await queryAsAdmin({ query: UPDATE_LOCAL_AUTH_QUERY, variables: { id: settingsInternalId, input: RESET_LOCKOUT_INPUT } });
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
  });
  it('should return the default lockout policy', async () => {
    const queryResult = await queryAsAdmin({ query: READ_LOCKOUT_QUERY, variables: {} });
    const { settings } = queryResult.data;
    expect(settings.local_auth_lockout_enabled).toEqual(false);
    expect(settings.local_auth_lockout_max_attempts).toEqual(5);
    expect(settings.local_auth_lockout_window).toEqual(1440);
    expect(settings.local_auth_lockout_duration).toEqual(15);
    expect(settings.local_auth_lockout_max_duration).toEqual(180);
  });
  it('should update the lockout policy', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_LOCAL_AUTH_QUERY,
      variables: {
        id: settingsInternalId,
        input: {
          enabled: true,
          local_auth_lockout_enabled: true,
          local_auth_lockout_max_attempts: 3,
          local_auth_lockout_window: 60,
          local_auth_lockout_duration: 10,
          local_auth_lockout_max_duration: 120,
        },
      },
    });
    const settings = queryResult.data.settingsEdit.updateLocalAuth;
    expect(settings.local_auth.enabled).toEqual(true);
    expect(settings.local_auth_lockout_enabled).toEqual(true);
    expect(settings.local_auth_lockout_max_attempts).toEqual(3);
    expect(settings.local_auth_lockout_window).toEqual(60);
    expect(settings.local_auth_lockout_duration).toEqual(10);
    expect(settings.local_auth_lockout_max_duration).toEqual(120);
  });
  it('should keep the lockout policy when the input omits it', async () => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_LOCAL_AUTH_QUERY,
      variables: { id: settingsInternalId, input: { enabled: true, local_auth_lockout_max_attempts: 4 } },
    });
    const settings = queryResult.data.settingsEdit.updateLocalAuth;
    expect(settings.local_auth_lockout_enabled).toEqual(true);
    expect(settings.local_auth_lockout_max_attempts).toEqual(4);
    expect(settings.local_auth_lockout_window).toEqual(60);
    expect(settings.local_auth_lockout_duration).toEqual(10);
    expect(settings.local_auth_lockout_max_duration).toEqual(120);
  });
  it.each([
    ['max attempts lower than 1', { local_auth_lockout_max_attempts: 0 }, 'Lockout max attempts must be greater than or equal to 1'],
    ['window equal to 0', { local_auth_lockout_window: 0 }, 'Lockout window must be greater than 0'],
    ['negative duration', { local_auth_lockout_duration: -5 }, 'Lockout duration must be greater than 0'],
    ['max duration equal to 0', { local_auth_lockout_max_duration: 0 }, 'Lockout max duration must be greater than 0'],
    ['window above 24 hours', { local_auth_lockout_window: 1441 }, 'Lockout window must be lower than or equal to 1440'],
    ['max duration above 3 hours', { local_auth_lockout_max_duration: 181 }, 'Lockout max duration must be lower than or equal to 180'],
    ['duration greater than max duration', { local_auth_lockout_duration: 200, local_auth_lockout_max_duration: 120 }, 'Lockout duration must be lower than or equal to lockout max duration'],
    ['duration greater than the stored max duration', { local_auth_lockout_duration: 121 }, 'Lockout duration must be lower than or equal to lockout max duration'],
  ])('should reject a lockout policy with %s', async (_, lockoutInput, expectedMessage) => {
    const queryResult = await queryAsAdmin({
      query: UPDATE_LOCAL_AUTH_QUERY,
      variables: { id: settingsInternalId, input: { enabled: true, ...lockoutInput } },
    });
    expect(queryResult.errors).toBeDefined();
    expect(queryResult.errors[0].message).toEqual(expectedMessage);
    // Nothing is patched
    const readResult = await queryAsAdmin({ query: READ_LOCKOUT_QUERY, variables: {} });
    expect(readResult.data.settings.local_auth_lockout_max_attempts).toEqual(4);
    expect(readResult.data.settings.local_auth_lockout_duration).toEqual(10);
    expect(readResult.data.settings.local_auth_lockout_max_duration).toEqual(120);
  });
  it('should reject a lockout policy edited through fieldPatch, bypassing its validation', async () => {
    await queryAsUserIsExpectedForbidden(USER_SECURITY, {
      query: EDIT_FIELD_QUERY,
      variables: { id: settingsInternalId, input: { key: 'local_auth_lockout_max_attempts', value: ['0'] } },
    });
    const readResult = await queryAsAdmin({ query: READ_LOCKOUT_QUERY, variables: {} });
    expect(readResult.data.settings.local_auth_lockout_max_attempts).toEqual(4);
  });
  it('should reject a lockout policy edited through fieldPatch, even with the BYPASS capability', async () => {
    const queryResult = await queryAsAdmin({
      query: EDIT_FIELD_QUERY,
      variables: { id: settingsInternalId, input: { key: 'local_auth_lockout_max_attempts', value: ['0'] } },
    });
    expect(queryResult.errors).toBeDefined();
    expect(queryResult.errors[0].message).toEqual('Local authentication lockout settings can only be edited through updateLocalAuth');
    const readResult = await queryAsAdmin({ query: READ_LOCKOUT_QUERY, variables: {} });
    expect(readResult.data.settings.local_auth_lockout_max_attempts).toEqual(4);
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

describe('Settings map source management', () => {
  const MAP_SOURCE_SETTINGS_QUERY = gql`
    query settings {
      settings {
        id
        platform_map_custom_file {
          name
          size
        }
      }
    }
  `;

  const MAP_CUSTOM_FILE_UPLOAD = gql`
    mutation SettingsMapCustomFileUpload($id: ID!, $file: Upload!) {
      settingsEdit(id: $id) {
        uploadMapCustomFile(file: $file) {
          id
          platform_map_custom_file {
            name
            size
          }
        }
      }
    }
  `;

  const MAP_CUSTOM_FILE_DELETE = gql`
    mutation SettingsMapCustomFileDelete($id: ID!) {
      settingsEdit(id: $id) {
        deleteMapCustomFile {
          id
          platform_map_custom_file {
            name
            size
          }
        }
      }
    }
  `;

  const settingsId = async () => {
    const queryResult = await queryAsAdmin({ query: MAP_SOURCE_SETTINGS_QUERY });
    return queryResult.data.settings.id;
  };

  it('should have no custom file initially', async () => {
    const queryResult = await queryAsAdmin({ query: MAP_SOURCE_SETTINGS_QUERY });
    expect(queryResult.data.settings.platform_map_custom_file).toBeNull();
  });

  it('should upload a map file to S3', async () => {
    const id = await settingsId();
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    const upload = await createUploadFromTestDataFile('test-map-file.pmtiles', 'test-map-file.pmtiles', 'application/octet-stream');
    const queryResult = await queryAsAdmin({
      query: MAP_CUSTOM_FILE_UPLOAD,
      variables: { id, file: upload },
    });
    expect(queryResult.errors).toBeUndefined();
    const customFile = queryResult.data.settingsEdit.uploadMapCustomFile.platform_map_custom_file;
    expect(customFile).not.toBeNull();
    expect(customFile.name).toEqual('test-map-file.pmtiles');
    expect(customFile.size).toBeGreaterThan(0);
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

  it('should mark the range not satisfiable when downloadFileRange gets an out-of-bounds range', async () => {
    const fullResult = await downloadFileRange('maps/world.pmtiles');
    const totalSize = fullResult.totalSize;
    fullResult.stream.destroy();

    const result = await downloadFileRange('maps/world.pmtiles', `bytes=${totalSize + 100}-${totalSize + 200}`);
    expect(result).not.toBeNull();
    expect(result.rangeNotSatisfiable).toBe(true);
    result.stream.destroy();
  });

  it('should delete the S3 map file', async () => {
    const id = await settingsId();
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    const queryResult = await queryAsAdmin({
      query: MAP_CUSTOM_FILE_DELETE,
      variables: { id },
    });
    expect(queryResult.errors).toBeUndefined();
    expect(queryResult.data.settingsEdit.deleteMapCustomFile.platform_map_custom_file).toBeNull();
  });

  it('should have no custom file after deletion', async () => {
    const queryResult = await queryAsAdmin({ query: MAP_SOURCE_SETTINGS_QUERY });
    expect(queryResult.data.settings.platform_map_custom_file).toBeNull();
  });
});

describe('Settings countries source management', () => {
  const COUNTRIES_SETTINGS_QUERY = gql`
    query settings {
      settings {
        id
        platform_map_countries_custom_file {
          name
          size
        }
      }
    }
  `;

  const COUNTRIES_CUSTOM_FILE_UPLOAD = gql`
    mutation SettingsCountriesCustomFileUpload($id: ID!, $file: Upload!) {
      settingsEdit(id: $id) {
        uploadCountriesCustomFile(file: $file) {
          id
          platform_map_countries_custom_file {
            name
            size
          }
        }
      }
    }
  `;

  const COUNTRIES_CUSTOM_FILE_DELETE = gql`
    mutation SettingsCountriesCustomFileDelete($id: ID!) {
      settingsEdit(id: $id) {
        deleteCountriesCustomFile {
          id
          platform_map_countries_custom_file {
            name
            size
          }
        }
      }
    }
  `;

  const settingsId = async () => {
    const queryResult = await queryAsAdmin({ query: COUNTRIES_SETTINGS_QUERY });
    return queryResult.data.settings.id;
  };

  const uploadCountries = async (relativePath, fileName, mimetype) => {
    const id = await settingsId();
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    const upload = await createUploadFromTestDataFile(relativePath, fileName, mimetype);
    return queryAsAdmin({
      query: COUNTRIES_CUSTOM_FILE_UPLOAD,
      variables: { id, file: upload },
    });
  };

  const storedContent = async () => {
    const stream = await downloadFile('maps/countries.json.gz');
    const chunks = [];
    for await (const chunk of stream) {
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  };

  it('should have no custom countries file initially', async () => {
    const queryResult = await queryAsAdmin({ query: COUNTRIES_SETTINGS_QUERY });
    expect(queryResult.data.settings.platform_map_countries_custom_file).toBeNull();
  });

  it('should upload a plain GeoJSON file and store it gzipped', async () => {
    const queryResult = await uploadCountries('test-countries.json', 'test-countries.json', 'application/json');
    expect(queryResult.errors).toBeUndefined();
    const customFile = queryResult.data.settingsEdit.uploadCountriesCustomFile.platform_map_countries_custom_file;
    expect(customFile).not.toBeNull();
    expect(customFile.name).toEqual('test-countries.json');
    expect(customFile.size).toBeGreaterThan(0);

    const content = await storedContent();
    expect(content[0]).toEqual(0x1f);
    expect(content[1]).toEqual(0x8b);
    const collection = JSON.parse(gunzipSync(content).toString('utf8'));
    expect(collection.features.map((f) => f.properties.ISO3)).toEqual(['FRA', 'DEU']);
  });

  it('should accept an already gzipped file and store it gzipped once', async () => {
    const queryResult = await uploadCountries('test-countries.json.gz', 'test-countries.json.gz', 'application/gzip');
    expect(queryResult.errors).toBeUndefined();
    const customFile = queryResult.data.settingsEdit.uploadCountriesCustomFile.platform_map_countries_custom_file;
    expect(customFile.name).toEqual('test-countries.json');

    const content = await storedContent();
    const collection = JSON.parse(gunzipSync(content).toString('utf8'));
    expect(collection.type).toEqual('FeatureCollection');
    expect(collection.features.length).toEqual(2);
  });

  it('should reject a file whose features have no ISO3 property', async () => {
    const queryResult = await uploadCountries('test-countries-invalid.json', 'test-countries-invalid.json', 'application/json');
    expect(queryResult.errors).toBeDefined();
    expect(queryResult.errors[0].message).toContain('ISO3');
  });

  it('should reject a file that is not valid JSON', async () => {
    const queryResult = await uploadCountries('test-map-file.pmtiles', 'test-map-file.pmtiles', 'application/octet-stream');
    expect(queryResult.errors).toBeDefined();
    expect(queryResult.errors[0].message).toContain('not valid JSON');
  });

  it('should delete the S3 countries file', async () => {
    const id = await settingsId();
    resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    const queryResult = await queryAsAdmin({
      query: COUNTRIES_CUSTOM_FILE_DELETE,
      variables: { id },
    });
    expect(queryResult.errors).toBeUndefined();
    expect(queryResult.data.settingsEdit.deleteCountriesCustomFile.platform_map_countries_custom_file).toBeNull();
  });

  it('should have no custom countries file after deletion', async () => {
    const queryResult = await queryAsAdmin({ query: COUNTRIES_SETTINGS_QUERY });
    expect(queryResult.data.settings.platform_map_countries_custom_file).toBeNull();
  });
});
