import { GraphQLDateTime } from 'graphql-iso-date';
import { importSchema } from 'graphql-import';
import { mergeResolvers } from 'merge-graphql-schemas';
import { makeExecutableSchema } from 'graphql-tools';
// noinspection NodeJsCodingAssistanceForCoreModules
import path from 'path';
import settingsResolvers from '../resolvers/settings';
import userResolvers from '../resolvers/user';
import groupResolvers from '../resolvers/group';
import markingDefinitionResolvers from '../resolvers/markingDefinition';
import externalReferenceResolvers from '../resolvers/externalReference';
import killChainPhaseResolvers from '../resolvers/killChainPhase';
import identityResolvers from '../resolvers/identity';
import threatActorResolvers from '../resolvers/threatActor';
import intrusionSetResolvers from '../resolvers/intrusionSet';
import malwareResolvers from '../resolvers/malware';
import reportResolvers from '../resolvers/report';

const globalResolvers = {
  DateTime: GraphQLDateTime
};

const schemaPath = path.join(__dirname, '../../config/schema/opencti.graphql');
const typeDefs = importSchema(schemaPath);

const resolvers = mergeResolvers([
  globalResolvers,
  settingsResolvers,
  userResolvers,
  groupResolvers,
  markingDefinitionResolvers,
  externalReferenceResolvers,
  killChainPhaseResolvers,
  identityResolvers,
  threatActorResolvers,
  intrusionSetResolvers,
  malwareResolvers,
  reportResolvers
]);

const schema = makeExecutableSchema({
  typeDefs,
  resolvers
});

export default schema;
