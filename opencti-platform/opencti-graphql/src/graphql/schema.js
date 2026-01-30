import { ApolloServerErrorCode } from '@apollo/server/errors';
import { GraphQLError, GraphQLScalarType, Kind } from 'graphql';
import { GraphQLDateTime } from 'graphql-scalars';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { constraintDirectiveDocumentation, constraintDirectiveTypeDefs } from 'graphql-constraint-directive';
import { validate as uuidValidate } from 'uuid';
import GraphQLUpload from 'graphql-upload/GraphQLUpload.mjs';
import { mergeResolvers } from '@graphql-tools/merge';
import { rateLimitDirective } from 'graphql-rate-limit-directive';
import settingsResolvers from '../resolvers/settings';
import logResolvers from '../resolvers/log';
import attributeResolvers from '../resolvers/attribute';
import subTypeResolvers from '../resolvers/subType';
import labelResolvers from '../resolvers/label';
import rabbitmqMetricsResolvers from '../resolvers/rabbitmqMetrics';
import elasticSearchMetricsResolvers from '../resolvers/elasticSearchMetrics';
import internalObjectResolvers from '../resolvers/internalObject';
import stixObjectOrStixRelationshipOrCreatorResolvers from '../resolvers/stixObjectOrStixRelationshipOrCreator';
import stixObjectOrStixRelationshipResolvers from '../resolvers/stixObjectOrStixRelationship';
import stixCoreObjectResolvers from '../resolvers/stixCoreObject';
import stixDomainObjectResolvers from '../resolvers/stixDomainObject';
import stixCyberObservableResolvers from '../resolvers/stixCyberObservable';
import internalRelationshipResolvers from '../resolvers/internalRelationship';
import stixRelationshipResolvers from '../resolvers/stixRelationship';
import stixCoreRelationshipResolvers from '../resolvers/stixCoreRelationship';
import stixSightingRelationshipResolvers from '../resolvers/stixSightingRelationship';
import identityResolvers from '../resolvers/identity';
import individualResolvers from '../resolvers/individual';
import userResolvers from '../resolvers/user';
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
import indicatorResolvers from '../modules/indicator/indicator-resolver';
import incidentResolvers from '../resolvers/incident';
import { authDirectiveBuilder } from './authDirective';
import connectorResolvers from '../resolvers/connector';
import fileResolvers from '../resolvers/file';
import indexedFileResolvers from '../resolvers/indexedFile';
import globalTypeDefs from '../../config/schema/opencti.graphql';
import organizationOrIndividualResolvers from '../resolvers/organizationOrIndividual';
import taxiiResolvers from '../resolvers/taxii';
import feedResolvers from '../resolvers/feed';
import taskResolvers from '../resolvers/backgroundTask';
import retentionResolvers from '../resolvers/retentionRule';
import streamResolvers from '../resolvers/stream';
import statusResolvers from '../resolvers/status';
import ruleResolvers from '../resolvers/rule';
import stixResolvers from '../resolvers/stix';
import { isSupportedStixType } from '../schema/identifier';
import stixRefRelationshipResolvers from '../resolvers/stixRefRelationship';
import stixMetaObjectResolvers from '../resolvers/stixMetaObject';
import filterKeysSchemaResolver from '../resolvers/filterKeysSchema';
import basicObjectResolvers from '../resolvers/basicObject';
import { FunctionalError } from '../config/errors';
import inferredObjectResolvers from '../resolvers/inferredObject';

const schemaTypeDefs = [globalTypeDefs];

const validateStixId = (stixId) => {
  if (!stixId.includes('--')) {
    throw new GraphQLError(`Provided value ${stixId} is not a valid STIX ID`, { extensions: { code: ApolloServerErrorCode.BAD_USER_INPUT } });
  }
  const [type, uuid] = stixId.split('--');
  if (!isSupportedStixType(type.replace('x-mitre-', '').replace('x-opencti-', ''))) {
    throw new GraphQLError(`Provided value ${stixId} is not a valid STIX ID (type ${type} not supported)`, { extensions: { code: ApolloServerErrorCode.BAD_USER_INPUT } });
  }
  if (!uuidValidate(uuid)) {
    throw new GraphQLError(`Provided value ${stixId} is not a valid STIX ID (UUID not valid)`, { extensions: { code: ApolloServerErrorCode.BAD_USER_INPUT } });
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
  throw new GraphQLError('Provided value is not a valid STIX Reference', { extensions: { code: ApolloServerErrorCode.BAD_USER_INPUT } });
};

const parseObject = (ast) => {
  const value = Object.create(null);
  ast.fields.forEach((field) => {
    value[field.name.value] = parseAst(field.value);
  });
  return value;
};

const parseAst = (ast) => {
  switch (ast.kind) {
    case Kind.STRING:
    case Kind.BOOLEAN:
      return ast.value;
    case Kind.INT:
      return parseInt(ast.value, 10);
    case Kind.FLOAT:
      return parseFloat(ast.value);
    case Kind.OBJECT:
      return parseObject(ast);
    case Kind.LIST:
      return ast.values.map(parseAst);
    default:
      return null;
  }
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
      throw new GraphQLError('Provided value is not a valid STIX ID', { extensions: { code: ApolloServerErrorCode.BAD_USER_INPUT } });
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
      throw new GraphQLError('Provided value is not a valid STIX ID', { extensions: { code: ApolloServerErrorCode.BAD_USER_INPUT } });
    },
  }),
  Any: new GraphQLScalarType({
    name: 'Any',
    description: 'Arbitrary object',
    serialize: () => {
      throw new GraphQLError('Any serialization unsupported.');
    },
    parseValue: (value) => value,
    parseLiteral: (ast) => parseAst(ast),
  }),
};
const schemaResolvers = [
  // EXTERNAL
  constraintDirectiveTypeDefs,
  // INTERNAL
  globalResolvers,
  inferredObjectResolvers,
  taxiiResolvers,
  feedResolvers,
  streamResolvers,
  statusResolvers,
  logResolvers,
  rabbitmqMetricsResolvers,
  elasticSearchMetricsResolvers,
  attributeResolvers,
  subTypeResolvers,
  filterKeysSchemaResolver,
  fileResolvers,
  indexedFileResolvers,
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
  basicObjectResolvers,
  // STIX META OBJECT ENTITIES
  stixMetaObjectResolvers,
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
  // STIX CORE RELATIONSHIPS
  stixCoreRelationshipResolvers,
  // STIX SIGHTING RELATIONSHIPS
  stixSightingRelationshipResolvers,
  // STIX REF RELATIONSHIPS
  stixRefRelationshipResolvers,
  // ALL
  organizationOrIndividualResolvers,
  stixObjectOrStixRelationshipResolvers,
  stixObjectOrStixRelationshipOrCreatorResolvers,
];
export const registerGraphqlSchema = ({ schema, resolver }) => {
  schemaTypeDefs.push(schema);
  schemaResolvers.push(resolver);
};

// enabling rate-limit on specific queries with directive @rateLimit
const { rateLimitDirectiveTypeDefs, rateLimitDirectiveTransformer } = rateLimitDirective({
  onLimit: () => {
    throw FunctionalError('Too many requests');
  },
});
schemaTypeDefs.push(rateLimitDirectiveTypeDefs);

const createSchema = () => {
  const resolvers = mergeResolvers(schemaResolvers);
  const { authDirectiveTransformer } = authDirectiveBuilder('auth');
  let schema = makeExecutableSchema({
    typeDefs: schemaTypeDefs,
    resolvers,
    inheritResolversFromInterfaces: true,
  });
  schema = constraintDirectiveDocumentation()(schema);
  schema = rateLimitDirectiveTransformer(authDirectiveTransformer(schema));
  return schema;
};

export default createSchema;
