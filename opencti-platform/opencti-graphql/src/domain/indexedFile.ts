/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { getStats } from '../database/engine';
import { READ_INDEX_FILES } from '../database/utils';
import { getManagerConfigurationFromCache, managerConfigurationEditField } from '../modules/managerConfiguration/managerConfiguration-domain';
import { FunctionalError } from '../config/errors';
import { publishUserAction } from '../listener/UserActionListener';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from '../modules/managerConfiguration/managerConfiguration-types';
import { elCountFiles, elDeleteAllFiles, elSearchFiles } from '../database/file-search';
import type { AuthContext, AuthUser } from '../types/user';
import type { QueryIndexedFilesArgs, QueryIndexedFilesCountArgs } from '../generated/graphql';

export const indexedFilesMetrics = async () => {
  const metrics = await getStats([READ_INDEX_FILES]);
  return {
    globalCount: metrics.docs.count,
    globalSize: metrics.store.size_in_bytes,
  };
};

export const countIndexedFiles = async (context: AuthContext, user: AuthUser, args: QueryIndexedFilesCountArgs) => {
  return elCountFiles(context, context.user, args);
};

export const searchIndexedFiles = async (context: AuthContext, user: AuthUser, args: QueryIndexedFilesArgs) => {
  return elSearchFiles(context, context.user, args);
};

export const resetFileIndexing = async (context: AuthContext, user: AuthUser) => {
  const managerConfiguration = await getManagerConfigurationFromCache(context, user, 'FILE_INDEX_MANAGER');
  if (!managerConfiguration) {
    throw FunctionalError('No manager configuration found');
  }
  const managerConfigurationEditInput = [
    { key: 'manager_running', value: [false] },
    { key: 'last_run_start_date', value: [null] },
    { key: 'last_run_end_date', value: [null] },
  ];
  await managerConfigurationEditField(context, user, managerConfiguration.id, managerConfigurationEditInput);
  await elDeleteAllFiles();
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: 'Reset file indexing',
    context_data: { id: managerConfiguration.id, entity_type: ENTITY_TYPE_MANAGER_CONFIGURATION, input: {} },
  });
  return true;
};
