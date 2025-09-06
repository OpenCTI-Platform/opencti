import { IngestionAuthType } from '../../generated/graphql';
import { FunctionalError } from '../../config/errors';

export const verifyIngestionAuthenticationContent = (authenticationType: string, authenticationValue: string) => {
  if (authenticationType && authenticationValue) {
    if (authenticationType === IngestionAuthType.Basic && authenticationValue.split(':').length !== 2) {
      throw FunctionalError('Username and password cannot have : character.', { authenticationType });
    }

    if (authenticationType === IngestionAuthType.Certificate && authenticationValue.split(':').length !== 3) {
      throw FunctionalError('Certificate, CA and Key cannot have : character.', { authenticationType });
    }
  }
};

export const removeAuthenticationCredentials = (authentication_type: IngestionAuthType | undefined | null, authentication_value: string | undefined | null) => {
  if (!authentication_value || !authentication_type) {
    return authentication_value;
  }
  if (authentication_type === IngestionAuthType.Bearer) {
    return 'undefined';
  }
  const authenticationValueSplit = authentication_value.split(':');
  if (authentication_type === IngestionAuthType.Basic) {
    return [authenticationValueSplit[0], 'undefined'].join(':');
  }
  if (authentication_type === IngestionAuthType.Certificate) {
    return [authenticationValueSplit[0], 'undefined', authenticationValueSplit[2]].join(':');
  }
  return authentication_value;
};

export const addAuthenticationCredentials = (currentValue: string | undefined | null, newValue: string | undefined | null, authType: IngestionAuthType) => {
  if (!newValue) {
    return currentValue;
  }
  if (!currentValue) {
    return newValue;
  }
  if (authType === IngestionAuthType.Bearer) {
    // For bearer, the entire value is just the token
    return newValue !== 'undefined' ? newValue : currentValue;
  }

  const currentParts = currentValue.split(':');
  const newParts = newValue.split(':');

  if (authType === IngestionAuthType.Basic) {
    // Basic auth format: username:password
    return [
      newParts[0],
      newParts[1] && newParts[1] !== 'undefined' ? newParts[1] : currentParts[1],
    ].join(':');
  }

  if (authType === IngestionAuthType.Certificate) {
    // Certificate format: cert:key:ca
    return [
      newParts[0],
      newParts[1] && newParts[1] !== 'undefined' ? newParts[1] : currentParts[1],
      newParts[2],
    ].join(':');
  }

  return currentValue;
};
