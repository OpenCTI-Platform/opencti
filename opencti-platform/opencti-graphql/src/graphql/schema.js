import { GraphQLDateTime } from 'graphql-scalars';
import { mergeResolvers } from 'merge-graphql-schemas';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { constraintDirective } from 'graphql-constraint-directive';
// eslint-disable-next-line import/extensions
import { GraphQLScalarType, Kind } from 'graphql/index.js';
import { validate as uuidValidate } from 'uuid';
import { UserInputError } from 'apollo-server-express';
import GraphQLUpload from 'graphql-upload/GraphQLUpload.mjs';
import settingsResolvers from '../resolvers/settings';
import logResolvers from '../resolvers/log';
import attributeResolvers from '../resolvers/attribute';
import workspaceResolvers from '../resolvers/workspace';
import subTypeResolvers from '../resolvers/subType';
import labelResolvers from '../resolvers/label';
import rabbitmqMetricsResolvers from '../resolvers/rabbitmqMetrics';
import elasticSearchMetricsResolvers from '../resolvers/elasticSearchMetrics';
import internalObjectResolvers from '../resolvers/internalObject';
import stixObjectOrStixRelationshipResolvers from '../resolvers/stixObjectOrStixRelationship';
import stixCoreObjectResolvers from '../resolvers/stixCoreObject';
import stixDomainObjectResolvers from '../resolvers/stixDomainObject';
import stixCyberObservableResolvers from '../resolvers/stixCyberObservable';
import internalRelationshipResolvers from '../resolvers/internalRelationship';
import stixRelationshipResolvers from '../resolvers/stixRelationship';
import stixMetaRelationshipResolvers from '../resolvers/stixMetaRelationship';
import stixCoreRelationshipResolvers from '../resolvers/stixCoreRelationship';
import stixSightingRelationshipResolvers from '../resolvers/stixSightingRelationship';
import stixCyberObservableRelationResolvers from '../resolvers/stixCyberObservableRelationship';
import identityResolvers from '../resolvers/identity';
import individualResolvers from '../resolvers/individual';
import userResolvers from '../resolvers/user';
import organizationResolvers from '../resolvers/organization';
import sectorResolvers from '../resolvers/sector';
import systemResolvers from '../resolvers/system';
import locationResolvers from '../resolvers/location';
import cityResolvers from '../resolvers/city';
import countryResolvers from '../resolvers/country';
import regionResolvers from '../resolvers/region';
import positionResolvers from '../resolvers/position';
import groupResolvers from '../resolvers/group';
import markingDefinitionResolvers from '../resolvers/markingDefinition';
import externalReferenceResolvers from '../resolvers/externalReference';
import killChainPhaseResolvers from '../resolvers/killChainPhase';
import attackPatternResolvers from '../resolvers/attackPattern';
import courseOfActionResolvers from '../resolvers/courseOfAction';
import threatActorResolvers from '../resolvers/threatActor';
import intrusionSetResolvers from '../resolvers/intrusionSet';
import infrastructureResolvers from '../resolvers/infrastructure';
import campaignResolvers from '../resolvers/campaign';
import malwareResolvers from '../resolvers/malware';
import toolResolvers from '../resolvers/tool';
import vulnerabilityResolvers from '../resolvers/vulnerability';
import reportResolvers from '../resolvers/report';
import containerResolvers from '../resolvers/container';
import noteResolvers from '../resolvers/note';
import observedDataResolvers from '../resolvers/observedData';
import opinionResolvers from '../resolvers/opinion';
import indicatorResolvers from '../resolvers/indicator';
import incidentResolvers from '../resolvers/incident';
import { authDirectiveBuilder } from './authDirective';
import connectorResolvers from '../resolvers/connector';
import fileResolvers from '../resolvers/file';
import globalTypeDefs from '../../config/schema/opencti.graphql';
import organizationOrIndividualResolvers from '../resolvers/organizationOrIndividual';
import taxiiResolvers from '../resolvers/taxii';
import feedResolvers from '../resolvers/feed';
import taskResolvers from '../resolvers/task';
import retentionResolvers from '../resolvers/retentionRule';
import streamResolvers from '../resolvers/stream';
import statusResolvers from '../resolvers/status';
import ruleResolvers from '../resolvers/rule';
import stixResolvers from '../resolvers/stix';
import { isSupportedStixType } from '../schema/identifier';

const schemaTypeDefs = [globalTypeDefs];

const validateStixId = (stixId) => {
  if (!stixId.includes('--')) {
    throw new UserInputError('Provided value is not a valid STIX ID');
  }
  const [type, uuid] = stixId.split('--');
  if (!isSupportedStixType(type.replace('x-mitre-', ''))) {
    throw new UserInputError('Provided value is not a valid STIX ID (type not supported)');
  }
  if (!uuidValidate(uuid)) {
    throw new UserInputError('Provided value is not a valid STIX ID (UUID not valid)');
  }
  return stixId;
};

const validateStixRef = (stixRef) => {
  if (stixRef === null) {
    return stixRef;
  }
  if (stixRef.includes('--')) {
    return validateStixId(stixRef);
  }
  if (uuidValidate(stixRef)) {
    return stixRef;
  }
  throw new UserInputError('Provided value is not a valid STIX Reference');
};

const globalResolvers = {
  DateTime: GraphQLDateTime,
  Upload: GraphQLUpload,
  StixId: new GraphQLScalarType({
    name: 'StixId',
    description: 'STIX ID Scalar Type',
    serialize(value) {
      return value;
    },
    parseValue(value) {
      return validateStixId(value);
    },
    parseLiteral(ast) {
      if (ast.kind === Kind.STRING) {
        return validateStixId(ast.value);
      }
      throw new UserInputError('Provided value is not a valid STIX ID');
    },
  }),
  StixRef: new GraphQLScalarType({
    name: 'StixRef',
    description: 'STIX Reference Scalar Type',
    serialize(value) {
      return value;
    },
    parseValue(value) {
      return validateStixRef(value);
    },
    parseLiteral(ast) {
      if (ast.kind === Kind.STRING) {
        return validateStixRef(ast.value);
      }
      throw new UserInputError('Provided value is not a valid STIX ID');
    },
  }),
};
const schemaResolvers = [
  // INTERNAL
  globalResolvers,
  taxiiResolvers,
  feedResolvers,
  streamResolvers,
  statusResolvers,
  logResolvers,
  rabbitmqMetricsResolvers,
  elasticSearchMetricsResolvers,
  attributeResolvers,
  workspaceResolvers,
  subTypeResolvers,
  fileResolvers,
  taskResolvers,
  retentionResolvers,
  stixResolvers,
  // ENTITIES
  // INTERNAL OBJECT ENTITIES
  internalObjectResolvers,
  settingsResolvers,
  groupResolvers,
  userResolvers,
  connectorResolvers,
  // STIX OBJECT ENTITIES
  // STIX META OBJECT ENTITIES
  markingDefinitionResolvers,
  labelResolvers,
  externalReferenceResolvers,
  killChainPhaseResolvers,
  // STIX CORE OBJECT ENTITIES
  stixCoreObjectResolvers,
  // STIX DOMAIN OBJECT ENTITIES
  stixDomainObjectResolvers,
  attackPatternResolvers,
  campaignResolvers,
  // Containers
  containerResolvers,
  noteResolvers,
  observedDataResolvers,
  opinionResolvers,
  reportResolvers,
  courseOfActionResolvers,
  // Identities
  identityResolvers,
  individualResolvers,
  organizationResolvers,
  sectorResolvers,
  systemResolvers,
  // Others
  indicatorResolvers,
  infrastructureResolvers,
  intrusionSetResolvers,
  ruleResolvers,
  // Locations
  locationResolvers,
  cityResolvers,
  countryResolvers,
  regionResolvers,
  positionResolvers,
  // Others
  malwareResolvers,
  threatActorResolvers,
  toolResolvers,
  vulnerabilityResolvers,
  incidentResolvers,
  // STIX CYBER OBSERVABLE ENTITIES
  stixCyberObservableResolvers,
  // INTERNAL RELATIONSHIPS
  internalRelationshipResolvers,
  // STIX RELATIONSHIPS
  stixRelationshipResolvers,
  // STIX META RELATIONSHIPS
  stixMetaRelationshipResolvers,
  // STIX CORE RELATIONSHIPS
  stixCoreRelationshipResolvers,
  // STIX SIGHTING RELATIONSHIPS
  stixSightingRelationshipResolvers,
  // STIX CYBER OBSERVABLE RELATIONSHIPS
  stixCyberObservableRelationResolvers,
  // ALL
  organizationOrIndividualResolvers,
  stixObjectOrStixRelationshipResolvers,
];
export const registerGraphqlSchema = ({ schema, resolver }) => {
  schemaTypeDefs.push(schema);
  schemaResolvers.push(resolver);
};

const createSchema = () => {
  const resolvers = mergeResolvers(schemaResolvers);
  const { authDirectiveTransformer } = authDirectiveBuilder('auth');
  let schema = makeExecutableSchema({
    typeDefs: schemaTypeDefs,
    resolvers,
    inheritResolversFromInterfaces: true,
  });
  schema = constraintDirective()(schema);
  schema = authDirectiveTransformer(schema);
  return schema;
};

export default createSchema;
