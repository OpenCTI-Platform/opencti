import { FormikErrors } from 'formik';
import { IngestionCsvEditionForm } from '@components/data/ingestionCsv/IngestionCsvEdition';
import { IngestionJsonEditionForm } from '@components/data/ingestionJson/IngestionJsonEdition';

export const BASIC_AUTH = 'basic';
export const CERT_AUTH = 'certificate';
export const BEARER_AUTH = 'bearer';

export interface IngestionAuthValue {
  authentication_type: string,
  authentication_value?: string | null,
  username?: string,
  password?: string,
  cert?: string,
  key?: string,
  ca?: string,
}

/**
 * Compute content of authentication field depending on authentication type (see above constants).
 * @param values
 */
export const getAuthenticationValue = (values: IngestionAuthValue) => {
  let authenticationValue = values.authentication_value;
  if (values.authentication_type === BASIC_AUTH) {
    authenticationValue = `${values.username}:${values.password}`;
  } else if (values.authentication_type === CERT_AUTH) {
    authenticationValue = `${values.cert}:${values.key}:${values.ca}`;
  }
  return authenticationValue;
};

const extractAuthPart = (
  authentication_value: string | null | undefined,
  index: number,
  type: 'basic' | 'certificate' | 'bearer',
  partName: 'username' | 'password' | 'cert' | 'key' | 'ca' | 'token',
) => {
  if (!authentication_value) {
    return undefined;
  }

  const parts = authentication_value.split(':');

  // For password/key/ca/token, return undefined if the part is "undefined"
  if ((partName === 'password' || partName === 'key' || partName === 'ca' || partName === 'token')
    && parts[index] === 'undefined') {
    return undefined;
  }

  if ((type === 'basic' && parts.length !== 2) || (type === 'certificate' && parts.length !== 3)) {
    return undefined;
  }

  return parts[index] || undefined;
};

// For basic auth (username:password)
export const extractUsername = (authentication_value: string | null | undefined) => {
  return extractAuthPart(authentication_value, 0, 'basic', 'username');
};

export const extractPassword = (authentication_value: string | null | undefined) => {
  return extractAuthPart(authentication_value, 1, 'basic', 'password');
};

// For certificate auth (cert:key:ca)
export const extractCert = (authentication_value: string | null | undefined) => {
  return extractAuthPart(authentication_value, 0, 'certificate', 'cert');
};

export const extractKey = (authentication_value: string | null | undefined) => {
  return extractAuthPart(authentication_value, 1, 'certificate', 'key');
};

export const extractCA = (authentication_value: string | null | undefined) => {
  return extractAuthPart(authentication_value, 2, 'certificate', 'ca');
};

// For bearer auth (tokens)
export const extractToken = (authentication_value: string | null | undefined) => {
  return extractAuthPart(authentication_value, 0, 'bearer', 'token');
};

export const updateAuthenticationFields = async (
  setFieldValue: (field: string, value: string) => Promise<void | FormikErrors<IngestionJsonEditionForm | IngestionCsvEditionForm>>,
  value: string,
) => {
  // Reset every authentication values on type change
  await Promise.all([
    setFieldValue('authentication_type', value),
    setFieldValue('authentication_value', ''),
    setFieldValue('token', ''),
    setFieldValue('username', ''),
    setFieldValue('password', ''),
    setFieldValue('cert', ''),
    setFieldValue('key', ''),
    setFieldValue('ca', ''),
  ]);
};
