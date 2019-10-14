import { GraphQLDateTime } from 'graphql-iso-date';
import { importSchema } from 'graphql-import';
import { mergeResolvers } from 'merge-graphql-schemas';
import { makeExecutableSchema } from 'graphql-tools';
import ConstraintDirective from 'graphql-constraint-directive';
import path from 'path';
import settingsResolvers from '../resolvers/settings';
import attributeResolvers from '../resolvers/attribute';
import rabbitmqMetricsResolvers from '../resolvers/rabbitmqMetrics';
import globalObjectResolvers from '../resolvers/globalObject';
import stixEntityResolvers from '../resolvers/stixEntity';
import stixDomainEntityResolvers from '../resolvers/stixDomainEntity';
import stixObservableResolvers from '../resolvers/stixObservable';
import stixRelationResolvers from '../resolvers/stixRelation';
import workspaceResolvers from '../resolvers/workspace';
import identityResolvers from '../resolvers/identity';
import userResolvers from '../resolvers/user';
import organizationResolvers from '../resolvers/organization';
import sectorResolvers from '../resolvers/sector';
import cityResolvers from '../resolvers/city';
import countryResolvers from '../resolvers/country';
import regionResolvers from '../resolvers/region';
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
import toolResolvers from '../resolvers/tool';
import vulnerabilityResolvers from '../resolvers/vulnerability';
import reportResolvers from '../resolvers/report';
import AuthDirectives, { AUTH_DIRECTIVE } from './authDirective';
import connectorResolvers from '../resolvers/connector';
import fileResolvers from '../resolvers/File';

const globalResolvers = {
  DateTime: GraphQLDateTime
};

const schemaPath = path.join(__dirname, '../../config/schema/opencti.graphql');
const typeDefs = importSchema(schemaPath);

const resolvers = mergeResolvers([
  globalResolvers,
  settingsResolvers,
  attributeResolvers,
  rabbitmqMetricsResolvers,
  connectorResolvers,
  fileResolvers,
  globalObjectResolvers,
  stixEntityResolvers,
  stixDomainEntityResolvers,
  stixObservableResolvers,
  stixRelationResolvers,
  workspaceResolvers,
  identityResolvers,
  userResolvers,
  organizationResolvers,
  sectorResolvers,
  cityResolvers,
  countryResolvers,
  regionResolvers,
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
  toolResolvers,
  vulnerabilityResolvers,
  reportResolvers
]);

const schema = makeExecutableSchema({
  typeDefs,
  resolvers,
  schemaDirectives: {
    [AUTH_DIRECTIVE]: AuthDirectives,
    constraint: ConstraintDirective
  },
  inheritResolversFromInterfaces: true
});

export default schema;
