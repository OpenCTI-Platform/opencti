import { batchLoader } from '../../database/middleware';
import { batchCreator } from '../../domain/user';
import type { Resolvers } from '../../generated/graphql';
import {
  addIngestionJson,
  deleteIngestionJson,
  findAllPaginated,
  findById,
  findJsonMapperForIngestionById,
  ingestionJsonEditField,
  ingestionJsonResetState,
  testJsonIngestionMapping
} from './ingestion-json-domain';
import { connectorIdFromIngestId } from '../../domain/connector';

const creatorLoader = batchLoader(batchCreator);

const ingestionJsonResolvers: Resolvers = {
  Query: {
    ingestionJson: (_, { id }, context) => findById(context, context.user, id),
    ingestionJsons: (_, args, context) => findAllPaginated(context, context.user, args),
  },
  IngestionJson: {
    user: (ingestionJson, _, context) => creatorLoader.load(ingestionJson.user_id, context, context.user),
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
  },
};

export default ingestionJsonResolvers;
