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

import type { Resolvers } from '../../../generated/graphql';
import {
  createJsonMapper,
  deleteJsonMapper,
  fieldPatchJsonMapper,
  findJsonMapperPaginated,
  findById,
  getParsedRepresentations,
  jsonMapperExport,
  jsonMapperImport,
  jsonMapperTest
} from './jsonMapper-domain';
import { getJsonMapperErrorMessage } from './jsonMapper-utils';

const jsonMapperResolvers: Resolvers = {
  Query: {
    jsonMapper: (_, { id }, context) => findById(context, context.user, id),
    jsonMappers: (_, args, context) => findJsonMapperPaginated(context, context.user, args),
  },
  JsonMapper: {
    errors: (jsonMapper, _, context) => getJsonMapperErrorMessage(context, context.user, jsonMapper),
    representations: (jsonMapper, _, context) => getParsedRepresentations(context, context.user, jsonMapper),
    toConfigurationExport: (jsonMapper, _, context) => jsonMapperExport(context, context.user, jsonMapper),
  },
  Mutation: {
    jsonMapperAdd: (_, { input }, context) => {
      return createJsonMapper(context, context.user, input);
    },
    jsonMapperTest: (_, { configuration, file }, context) => {
      return jsonMapperTest(context, context.user, configuration, file);
    },
    jsonMapperImport: (_, { file }, context) => {
      return jsonMapperImport(context, context.user, file);
    },
    jsonMapperDelete: (_, { id }, context) => {
      return deleteJsonMapper(context, context.user, id);
    },
    jsonMapperFieldPatch: (_, { id, input }, context) => {
      return fieldPatchJsonMapper(context, context.user, id, input);
    },
  }
};

export default jsonMapperResolvers;
