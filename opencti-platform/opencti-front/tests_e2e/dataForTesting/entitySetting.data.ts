import { APIRequestContext } from '@playwright/test';
import { graphqlQuery } from './query-utils';

const entitySettingByTypeQuery = (targetType: string) => `
  query {
    entitySettingByType(targetType: "${targetType}") {
      id
    }
  }
`;

const patchEntitySettingMutation = (id: string, key: string, value: string) => `
  mutation {
    entitySettingsFieldPatch(ids: ["${id}"], input: [{ key: "${key}", value: "${value}" }]) {
      id
    }
  }
`;

/**
 * Set an explicit value on an entity setting (idempotent, unlike clicking
 * a UI toggle which inverts the current state).
 */
export const patchEntitySetting = async (
  request: APIRequestContext,
  targetType: string,
  key: string,
  value: string | boolean,
) => {
  const settingResponse = await graphqlQuery(request, entitySettingByTypeQuery(targetType));
  const settingData = await settingResponse.json();
  const settingId = settingData.data?.entitySettingByType?.id;
  if (!settingId) {
    throw new Error(`Cannot find entity setting for type ${targetType}: ${JSON.stringify(settingData.errors ?? settingData)}`);
  }
  const patchResponse = await graphqlQuery(request, patchEntitySettingMutation(settingId, key, String(value)));
  const patchData = await patchResponse.json();
  if (patchData.errors || !patchData.data?.entitySettingsFieldPatch) {
    throw new Error(`Cannot patch entity setting ${key} for type ${targetType}: ${JSON.stringify(patchData.errors ?? patchData)}`);
  }
  return patchData;
};
