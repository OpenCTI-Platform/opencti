import { PROVIDERS } from '../../../../src/modules/authenticationProvider/providers-configuration';
import { expect } from 'vitest';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { ENTITY_TYPE_AUTHENTICATION_PROVIDER } from '../../../../src/modules/authenticationProvider/authenticationProvider-types';
import { deleteElementById } from '../../../../src/database/middleware';

export const clearProvider = async () => {
  const elementsCount = PROVIDERS.length;
  for (let i = 0; i < elementsCount; i++) {
    PROVIDERS.pop();
  }
  expect(PROVIDERS).toStrictEqual([]);
};

export const clearAuthenticationProviderDatabase = async () => {
  // using low level function to escape EE checks
  const ssoInDb = await fullEntitiesList(testContext, ADMIN_USER, [ENTITY_TYPE_AUTHENTICATION_PROVIDER]);
  for (let i = 0; i < ssoInDb.length; i++) {
    await deleteElementById(testContext, ADMIN_USER, ssoInDb[i].id, ENTITY_TYPE_AUTHENTICATION_PROVIDER);
  }
};
