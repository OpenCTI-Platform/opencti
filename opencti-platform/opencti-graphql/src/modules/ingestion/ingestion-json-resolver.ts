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

import type { Resolvers } from '../../generated/graphql';
import {
  addIngestionJson,
  deleteIngestionJson,
  editIngestionJson,
  findJsonIngestionPaginated,
  findById,
  findJsonMapperForIngestionById,
  ingestionJsonEditField,
  ingestionJsonResetState,
  testJsonIngestionMapping
} from './ingestion-json-domain';
import { connectorIdFromIngestId } from '../../domain/connector';

const ingestionJsonResolvers: Resolvers = {
  Query: {
    ingestionJson: (_, { id }, context) => findById(context, context.user, id, true),
    ingestionJsons: (_, args, context) => findJsonIngestionPaginated(context, context.user, args),
  },
  IngestionJson: {
    user: (ingestionJson, _, context) => context.batch.creatorBatchLoader.load(ingestionJson.user_id),
    connector_id: (ingestionJson) => connectorIdFromIngestId(ingestionJson.id),
    jsonMapper: (ingestionJson, _, context) => findJsonMapperForIngestionById(context, context.user, ingestionJson.json_mapper_id),
  },
  Mutation: {
    ingestionJsonTester: (_, { input }, context) => {
      return testJsonIngestionMapping(context, context.user, input);
    },
    ingestionJsonAdd: (_, { input }, context) => {
      return addIngestionJson(context, context.user, input);
    },
    ingestionJsonResetState: (_, { id }, context) => {
      return ingestionJsonResetState(context, context.user, id);
    },
    ingestionJsonDelete: (_, { id }, context) => {
      return deleteIngestionJson(context, context.user, id);
    },
    ingestionJsonFieldPatch: (_, { id, input }, context) => {
      return ingestionJsonEditField(context, context.user, id, input);
    },
    ingestionJsonEdit: (_, { id, input }, context) => {
      return editIngestionJson(context, context.user, id, input);
    },
  },
};

export default ingestionJsonResolvers;
