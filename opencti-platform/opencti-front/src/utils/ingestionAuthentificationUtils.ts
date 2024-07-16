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

// For basic auth, authentication_value = username:password
export const extractUsername = (authentication_value: string | null | undefined) => {
  return authentication_value ? authentication_value.split(':')[0] : undefined;
};

export const extractPassword = (authentication_value: string | null | undefined) => {
  return authentication_value ? authentication_value.split(':')[1] : undefined;
};

// For certificate auth, authentication_value = cert:key:ca
export const extractCert = (authentication_value: string | null | undefined) => {
  return authentication_value ? authentication_value.split(':')[0] : undefined;
};

export const extractKey = (authentication_value: string | null | undefined) => {
  return authentication_value ? authentication_value.split(':')[1] : undefined;
};

export const extractCA = (authentication_value: string | null | undefined) => {
  return authentication_value ? authentication_value.split(':')[2] : undefined;
};
