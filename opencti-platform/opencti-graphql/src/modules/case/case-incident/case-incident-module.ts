import type { ModuleDescriptor } from '../../module-descriptor';
import { CASE_INCIDENT_DEFINITION } from './case-incident';
import caseIncidentTypeDefs from './case-incident.graphql';
import caseIncidentResolvers from './case-incident-resolvers';

const caseIncidentModule: ModuleDescriptor = {
  id: 'caseIncident',
  dataModel: [CASE_INCIDENT_DEFINITION],
  graphqlSchemas: [{ schema: caseIncidentTypeDefs, resolver: caseIncidentResolvers }],
};

export default caseIncidentModule;
