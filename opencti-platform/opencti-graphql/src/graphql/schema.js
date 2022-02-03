import { mergeResolvers } from '@graphql-tools/merge';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { constraintDirective } from 'graphql-constraint-directive';
import {
  GraphQLDateTime,
  EmailAddressTypeDefinition,
  EmailAddressResolver,
  IPv4Definition,
  IPv4Resolver,
  IPv6Definition,
  IPv6Resolver,
  LatitudeDefinition,
  LatitudeResolver,
  LongitudeDefinition,
  LongitudeResolver,
  MACDefinition,
  MACResolver,
  PhoneNumberTypeDefinition,
  PhoneNumberResolver,
  PortDefinition,
  PortResolver,
  PositiveIntTypeDefinition,
  PositiveIntResolver,
  PostalCodeTypeDefinition,
  PostalCodeResolver,
  URLTypeDefinition,
  URLResolver,
  VoidTypeDefinition,
  VoidResolver,
} from 'graphql-scalars';
import {DateTimeScalar} from "./scalars";
import settingsResolvers from '../resolvers/settings';
import logResolvers from '../resolvers/log';
import attributeResolvers from '../resolvers/attribute';
import workspaceResolvers from '../resolvers/workspace';
import subTypeResolvers from '../resolvers/subType';
import labelResolvers from '../resolvers/label';
import amqpMetricsResolvers from '../resolvers/amqpMetrics';
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
import { authDirectiveV2 } from './authDirective';
import connectorResolvers from '../resolvers/connector';
import fileResolvers from '../resolvers/file';
import organizationOrIndividualResolvers from '../resolvers/organizationOrIndividual';
import taxiiResolvers from '../resolvers/taxii';
import taskResolvers from '../resolvers/task';
import streamResolvers from '../resolvers/stream';
import userSubscriptionResolvers from '../resolvers/userSubscription';
import statusResolvers from '../resolvers/status';
import ruleResolvers from '../resolvers/rule';
import stixResolvers from '../resolvers/stix';
// Import Cyio resolvers
import assetCommonResolvers from '../cyio/schema/assets/asset-common/resolvers.js';
import computingDeviceResolvers from '../cyio/schema/assets/computing-device/resolvers.js';
import networkResolvers from '../cyio/schema/assets/network/resolvers.js';
import softwareResolvers from '../cyio/schema/assets/software/resolvers.js';
import cyioExternalReferenceResolvers from '../schema/global/resolvers/externalReference.js';
import cyioLabelResolvers from '../schema/global/resolvers/label.js';
import cyioNoteResolvers from '../schema/global/resolvers/note.js';

// Cyio Extensions to support merged graphQL schema
import { loadSchemaSync } from '@graphql-tools/load';
import { GraphQLFileLoader } from '@graphql-tools/graphql-file-loader' ;

const {authDirectiveTransformer } = authDirectiveV2();

const createSchema = () => {

  const globalResolvers = {
    DateTime: GraphQLDateTime,
    Timestamp: DateTimeScalar,
    EmailAddress: EmailAddressResolver,
    IPv4: IPv4Resolver,
    IPv6: IPv6Resolver,
    Latitude: LatitudeResolver,
    Longitude: LongitudeResolver,
    MAC: MACResolver,
    PhoneNumber: PhoneNumberResolver,
    Port: PortResolver,
    PositiveInt: PositiveIntResolver,
    PostalCode: PostalCodeResolver,
    URL: URLResolver,
    Void: VoidResolver,
  };

  const resolvers = mergeResolvers([
    // INTERNAL
    globalResolvers,
    taxiiResolvers,
    streamResolvers,
    userSubscriptionResolvers,
    statusResolvers,
    logResolvers,
    amqpMetricsResolvers,
    elasticSearchMetricsResolvers,
    attributeResolvers,
    workspaceResolvers,
    subTypeResolvers,
    fileResolvers,
    taskResolvers,
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
    // CYIO
    assetCommonResolvers,
    computingDeviceResolvers,
    networkResolvers,
    softwareResolvers,
    cyioExternalReferenceResolvers,
    cyioLabelResolvers,
    cyioNoteResolvers,
]);

  // load the OpenCTI and each of the Cyio GraphQL schema files
  const typeDefs = loadSchemaSync('./**/**/*.graphql', {
    loaders: [new GraphQLFileLoader()],
  });

  let schema = makeExecutableSchema({
    typeDefs: [
      typeDefs,
      EmailAddressTypeDefinition,
      IPv4Definition,
      IPv6Definition,
      LatitudeDefinition,
      LongitudeDefinition,
      MACDefinition,
      PhoneNumberTypeDefinition,
      PortDefinition,
      PositiveIntTypeDefinition,
      PostalCodeTypeDefinition,
      URLTypeDefinition,
      VoidTypeDefinition,
    ],
    resolvers,
    schemaTransforms: [constraintDirective()],
    inheritResolversFromInterfaces: true,
  });
  schema = authDirectiveTransformer(schema);
  return schema;
};

export default createSchema;
