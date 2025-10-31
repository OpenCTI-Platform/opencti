/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityPir, ENTITY_TYPE_PIR } from './pir-types';
import { getEntitiesMapFromCache } from '../../database/cache';
import { FunctionalError } from '../../config/errors';
import { isUserCanAccessStoreElement, isUserHasCapabilities, PIRAPI } from '../../utils/access';

/**
 * Helper function to check a user has access to a pir
 * and return the pir
 */
export const getPirWithAccessCheck = async (context: AuthContext, user: AuthUser, pirId?: string | null) => {
  // check EE
  await checkEnterpriseEdition(context);
  // check capabilities
  const hasCapa = isUserHasCapabilities(user, [PIRAPI]);
  if (!hasCapa) {
    throw FunctionalError('Unauthorized Pir access', { user: user.id });
  }
  // check user has access to the PIR (authorized members)
  if (!pirId) {
    throw FunctionalError('No Pir ID provided');
  }
  const pirs = await getEntitiesMapFromCache<BasicStoreEntityPir>(context, user, ENTITY_TYPE_PIR);
  const pir = pirs.get(pirId);
  if (!pir) {
    throw FunctionalError('No PIR found', { pirId });
  }
  const isUserCanAccessPir = await isUserCanAccessStoreElement(context, user, pir);
  if (!isUserCanAccessPir) {
    throw FunctionalError('No PIR found', { pirId });
  }
  return pir;
};
