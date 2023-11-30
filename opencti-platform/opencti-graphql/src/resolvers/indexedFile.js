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

import { indexedFilesMetrics, resetFileIndexing, searchIndexedFiles } from '../domain/indexedFile';
import { batchLoader } from '../database/middleware';
import { batchStixDomainObjects } from '../domain/stixDomainObject';

const domainLoader = batchLoader(batchStixDomainObjects);

const indexedFileResolvers = {
  Query: {
    indexedFilesMetrics: () => indexedFilesMetrics(),
    indexedFiles: (_, args, context) => searchIndexedFiles(context, context.user, args),
  },
  IndexedFile: {
    entity: (file, _, context) => domainLoader.load(file.entity_id, context, context.user),
  },
  Mutation: {
    resetFileIndexing: (_, __, context) => resetFileIndexing(context, context.user),
  }
};

export default indexedFileResolvers;
