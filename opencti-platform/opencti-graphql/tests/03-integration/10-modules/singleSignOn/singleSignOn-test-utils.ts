import { PROVIDERS } from '../../../../src/modules/singleSignOn/providers-configuration';
import { expect } from 'vitest';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { ENTITY_TYPE_SINGLE_SIGN_ON } from '../../../../src/modules/singleSignOn/singleSignOn-types';
import { deleteElementById } from '../../../../src/database/middleware';

export const clearProvider = async () => {
  const elementsCount = PROVIDERS.length;
  for (let i = 0; i < elementsCount; i++) {
    PROVIDERS.pop();
  }
  expect(PROVIDERS).toStrictEqual([]);
};

export const clearSsoDatabase = async () => {
  // using low level function to escape EE checks
  const ssoInDb = await fullEntitiesList(testContext, ADMIN_USER, [ENTITY_TYPE_SINGLE_SIGN_ON]);
  for (let i = 0; i < ssoInDb.length; i++) {
    await deleteElementById(testContext, ADMIN_USER, ssoInDb[i].id, ENTITY_TYPE_SINGLE_SIGN_ON);
  }
};
