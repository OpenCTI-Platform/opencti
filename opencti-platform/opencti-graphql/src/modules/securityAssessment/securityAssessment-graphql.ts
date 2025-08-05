import { registerGraphqlSchema } from '../../graphql/schema';
import securityAssessmentResolvers from './securityAssessment-resolver';
import securityAssessmentTypeDefs from './securityAssessment.graphql';

registerGraphqlSchema({
  schema: securityAssessmentTypeDefs,
  resolver: securityAssessmentResolvers,
});
