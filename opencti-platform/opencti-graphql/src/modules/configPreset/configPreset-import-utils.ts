import { getBaseUrl } from '../../config/conf';
import type { AuthContext } from '../../types/user';
import type { ConfigPresetImportField } from './configPreset-import-types';

const DATA_URL = /^data:([^;,]+);base64,(.*)$/;

// An image given as a data: URL is shown as its type and size
const describeValue = (value: string) => {
  const match = DATA_URL.exec(value);
  if (!match) {
    return value;
  }
  const bytes = Math.floor((match[2].length * 3) / 4);
  return `${match[1]} (${Math.max(1, Math.round(bytes / 1024))} KB)`;
};

const platformHost = (context: AuthContext) => {
  try {
    return new URL(getBaseUrl(context.req)).host;
  } catch {
    return null;
  }
};

const isExternalHost = (value: string, host: string | null) => {
  try {
    const url = new URL(value);
    return (url.protocol === 'http:' || url.protocol === 'https:') && url.host !== host;
  } catch {
    return false;
  }
};

// The fields of an item shown in the preview, in the order of the keys; urlKeys are the ones that hold a URL or an image
export const buildImportFields = (context: AuthContext, configuration: Record<string, unknown>, keys: string[], urlKeys: string[] = []): ConfigPresetImportField[] => {
  const host = platformHost(context);
  return keys.map((key) => {
    const value = configuration[key];
    if (typeof value !== 'string') {
      return { key, value: null, external_host: false };
    }
    return { key, value: describeValue(value), external_host: urlKeys.includes(key) && isExternalHost(value, host) };
  });
};

export const isNothingToImport = (configuration: Record<string, unknown>, keys: string[]) => {
  return keys.every((key) => configuration[key] === null || configuration[key] === undefined);
};

export const importFailureReason = (error: { issues: { path: PropertyKey[]; message: string }[] }) => {
  return error.issues.map((issue) => `${issue.path.map(String).join('.') || 'configuration'}: ${issue.message}`).join(', ');
};
