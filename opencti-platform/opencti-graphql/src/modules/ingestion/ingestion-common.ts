import { TaxiiAuthType } from '../../generated/graphql';
import { FunctionalError } from '../../config/errors';

export const verifyIngestionAuthenticationContent = (authenticationType: string, authenticationValue: string) => {
  if (authenticationType && authenticationValue) {
    if (authenticationType === TaxiiAuthType.Basic && authenticationValue.split(':').length !== 2) {
      throw FunctionalError('Username and password cannot have : character.', { authenticationType });
    }

    if (authenticationType === TaxiiAuthType.Certificate && authenticationValue.split(':').length !== 3) {
      throw FunctionalError('Certificate, CA and Key cannot have : character.', { authenticationType });
    }
  }
};
