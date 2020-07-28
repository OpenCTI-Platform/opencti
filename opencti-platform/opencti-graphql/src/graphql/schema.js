import { GraphQLDateTime } from 'graphql-iso-date';
import { mergeResolvers } from 'merge-graphql-schemas';
import { makeExecutableSchema } from 'graphql-tools';
import { constraintDirective } from 'graphql-constraint-directive';
import settingsResolvers from '../resolvers/settings';
import logResolvers from '../resolvers/log';
import inferenceResolvers from '../resolvers/inference';
import attributeResolvers from '../resolvers/attribute';
import subTypeResolvers from '../resolvers/subType';
import labelResolvers from '../resolvers/label';
import rabbitmqMetricsResolvers from '../resolvers/rabbitmqMetrics';
import stixObjectOrStixRelationshipResolvers from '../resolvers/stixObjectOrStixRelationship';
import stixCoreObjectResolvers from '../resolvers/stixCoreObject';
import stixDomainObjectResolvers from '../resolvers/stixDomainObject';
import stixCyberObservableResolvers from '../resolvers/stixCyberObservable';
import stixMetaRelationshipResolvers from '../resolvers/stixMetaRelationship';
import stixCoreRelationshipResolvers from '../resolvers/stixCoreRelationship';
import stixSightingRelationshipResolvers from '../resolvers/stixSightingRelationship';
import stixCyberObservableRelationResolvers from '../resolvers/stixCyberObservableRelationship';
import workspaceResolvers from '../resolvers/workspace';
import identityResolvers from '../resolvers/identity';
import individualResolvers from '../resolvers/individual';
import userResolvers from '../resolvers/user';
import organizationResolvers from '../resolvers/organization';
import sectorResolvers from '../resolvers/sector';
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
import noteResolvers from '../resolvers/note';
import observedDataResolvers from '../resolvers/observedData';
import opinionResolvers from '../resolvers/opinion';
import indicatorResolvers from '../resolvers/indicator';
import xOpenctiIncidentResolvers from '../resolvers/xOpenctiIncident';
import AuthDirectives, { AUTH_DIRECTIVE } from './authDirective';
import connectorResolvers from '../resolvers/connector';
import fileResolvers from '../resolvers/file';
import typeDefs from '../../config/schema/opencti.graphql';

const createSchema = () => {
  const globalResolvers = {
    DateTime: GraphQLDateTime,
  };

  const resolvers = mergeResolvers([
    // INTERNAL
    globalResolvers,
    logResolvers,
    rabbitmqMetricsResolvers,
    inferenceResolvers,
    attributeResolvers,
    subTypeResolvers,
    fileResolvers,
    // ENTITIES
    // INTERNAL OBJECT ENTITIES
    settingsResolvers,
    groupResolvers,
    userResolvers,
    connectorResolvers,
    workspaceResolvers,
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
    indicatorResolvers,
    infrastructureResolvers,
    intrusionSetResolvers,
    // Locations
    cityResolvers,
    countryResolvers,
    regionResolvers,
    positionResolvers,
    malwareResolvers,
    threatActorResolvers,
    toolResolvers,
    vulnerabilityResolvers,
    xOpenctiIncidentResolvers,
    // STIX CYBER OBSERVABLE ENTITIES
    stixCyberObservableResolvers,
    // STIX META RELATIONSHIPS
    stixMetaRelationshipResolvers,
    // STIX CORE RELATIONSHIPS
    stixCoreRelationshipResolvers,
    // STIX SIGHTING RELATIONSHIPS
    stixSightingRelationshipResolvers,
    // STIX CYBER OBSERVABLE RELATIONSHIPS
    stixCyberObservableRelationResolvers,
    // ALL
    stixObjectOrStixRelationshipResolvers,
  ]);

  return makeExecutableSchema({
    typeDefs,
    resolvers,
    schemaDirectives: {
      [AUTH_DIRECTIVE]: AuthDirectives,
    },
    schemaTransforms: [constraintDirective()],
    inheritResolversFromInterfaces: true,
  });
};

export default createSchema;
