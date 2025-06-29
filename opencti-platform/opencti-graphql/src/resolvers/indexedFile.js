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

import { countIndexedFiles, indexedFilesMetrics, resetFileIndexing, searchIndexedFiles } from '../domain/indexedFile';

const indexedFileResolvers = {
  Query: {
    indexedFilesMetrics: () => indexedFilesMetrics(),
    indexedFiles: (_, args, context) => searchIndexedFiles(context, context.user, args),
    indexedFilesCount: (_, args, context) => countIndexedFiles(context, context.user, args),
  },
  IndexedFile: {
    entity: (file, _, context) => context.batch.domainsBatchLoader.load(file.entity_id),
  },
  Mutation: {
    resetFileIndexing: (_, __, context) => resetFileIndexing(context, context.user),
  }
};

export default indexedFileResolvers;
