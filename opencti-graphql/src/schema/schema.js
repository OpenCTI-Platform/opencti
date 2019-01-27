import { GraphQLDateTime } from 'graphql-iso-date';
import { importSchema } from 'graphql-import';
import { mergeResolvers } from 'merge-graphql-schemas';
import { makeExecutableSchema } from 'graphql-tools';
import ConstraintDirective from 'graphql-constraint-directive';
// noinspection NodeJsCodingAssistanceForCoreModules
import path from 'path';
import settingsResolvers from '../resolvers/settings';
import globalObjectResolvers from '../resolvers/globalObject';
import stixDomainEntityResolvers from '../resolvers/stixDomainEntity';
import stixRelationResolvers from '../resolvers/stixRelation';
import workspaceResolvers from '../resolvers/workspace';
import identityResolvers from '../resolvers/identity';
import userResolvers from '../resolvers/user';
import organizationResolvers from '../resolvers/organization';
import sectorResolvers from '../resolvers/sector';
import cityResolvers from '../resolvers/city';
import countryResolvers from '../resolvers/country';
import groupResolvers from '../resolvers/group';
import markingDefinitionResolvers from '../resolvers/markingDefinition';
import externalReferenceResolvers from '../resolvers/externalReference';
import killChainPhaseResolvers from '../resolvers/killChainPhase';
import attackPatternResolvers from '../resolvers/attackPattern';
import courseOfActionResolvers from '../resolvers/courseOfAction';
import threatActorResolvers from '../resolvers/threatActor';
import intrusionSetResolvers from '../resolvers/intrusionSet';
import campaignResolvers from '../resolvers/campaign';
import incidentResolvers from '../resolvers/incident';
import malwareResolvers from '../resolvers/malware';
import toolRsolvers from '../resolvers/tool';
import vulnerabilityResolvers from '../resolvers/vulnerability';
import reportResolvers from '../resolvers/report';

const globalResolvers = {
  DateTime: GraphQLDateTime
};

const schemaPath = path.join(__dirname, '../../config/schema/opencti.graphql');
const typeDefs = importSchema(schemaPath);

const resolvers = mergeResolvers([
  globalResolvers,
  settingsResolvers,
  globalObjectResolvers,
  stixDomainEntityResolvers,
  stixRelationResolvers,
  workspaceResolvers,
  identityResolvers,
  userResolvers,
  organizationResolvers,
  sectorResolvers,
  cityResolvers,
  countryResolvers,
  groupResolvers,
  markingDefinitionResolvers,
  externalReferenceResolvers,
  killChainPhaseResolvers,
  attackPatternResolvers,
  courseOfActionResolvers,
  threatActorResolvers,
  intrusionSetResolvers,
  campaignResolvers,
  incidentResolvers,
  malwareResolvers,
  toolRsolvers,
  vulnerabilityResolvers,
  reportResolvers
]);

const schema = makeExecutableSchema({
  typeDefs,
  resolvers,
  schemaDirectives: { constraint: ConstraintDirective }
});

export default schema;
