import { GraphQLDateTime } from 'graphql-iso-date';
import { importSchema } from 'graphql-import';
import { mergeResolvers } from 'merge-graphql-schemas';
import { makeExecutableSchema } from 'graphql-tools';
// noinspection NodeJsCodingAssistanceForCoreModules
import path from 'path';
import settingsResolvers from '../resolvers/settings';
import identityResolvers from '../resolvers/identity';
import userResolvers from '../resolvers/user';
import organizationResolvers from '../resolvers/organization';
import sectorResolvers from '../resolvers/sector';
import groupResolvers from '../resolvers/group';
import stixDomainDefinitionResolvers from '../resolvers/stixDomain';
import markingDefinitionResolvers from '../resolvers/markingDefinition';
import externalReferenceResolvers from '../resolvers/externalReference';
import killChainPhaseResolvers from '../resolvers/killChainPhase';
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
  identityResolvers,
  userResolvers,
  organizationResolvers,
  sectorResolvers,
  groupResolvers,
  stixDomainDefinitionResolvers,
  markingDefinitionResolvers,
  externalReferenceResolvers,
  killChainPhaseResolvers,
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
