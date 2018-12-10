import { GraphQLDateTime } from 'graphql-iso-date';
import { importSchema } from 'graphql-import';
import { mergeResolvers } from 'merge-graphql-schemas';
import { makeExecutableSchema } from 'graphql-tools';
// noinspection NodeJsCodingAssistanceForCoreModules
import path from 'path';
import userResolvers from '../resolvers/user';
import groupResolvers from '../resolvers/group';
import markingDefinitionResolvers from '../resolvers/markingDefinition';
import killChainPhaseResolvers from '../resolvers/killChainPhase';
import threatActorResolvers from '../resolvers/threatActor';
import intrusionSetResolvers from '../resolvers/intrusionSet';
import malwareResolvers from '../resolvers/malware';

const globalResolvers = {
  DateTime: GraphQLDateTime
};

const schemaPath = path.join(__dirname, '../../config/schema/opencti.graphql');
const typeDefs = importSchema(schemaPath);

const resolvers = mergeResolvers([
  globalResolvers,
  userResolvers,
  groupResolvers,
  markingDefinitionResolvers,
  killChainPhaseResolvers,
  threatActorResolvers,
  intrusionSetResolvers,
  malwareResolvers
]);

const schema = makeExecutableSchema({
  typeDefs,
  resolvers
});

export default schema;
