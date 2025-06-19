import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { SecurityPlatformAnalysis_securityPlatform$key } from '@components/entities/securityPlatforms/__generated__/SecurityPlatformAnalysis_securityPlatform.graphql';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';

interface SecurityPlatformAnalysisComponentProps {
  securityPlatform: SecurityPlatformAnalysis_securityPlatform$key;
}
const SecurityPlatformAnalysisFragment = graphql`
    fragment SecurityPlatformAnalysis_securityPlatform on SecurityPlatform {
        id
        name
        x_opencti_aliases
        x_opencti_graph_data
    }
`;
const SecurityPlatformAnalysis: FunctionComponent<SecurityPlatformAnalysisComponentProps> = ({ securityPlatform }) => {
  const securityPlatformAnalysis = useFragment(SecurityPlatformAnalysisFragment, securityPlatform);

  return (
    <StixCoreObjectOrStixCoreRelationshipContainers
      stixDomainObjectOrStixCoreRelationship={securityPlatformAnalysis}
    />
  );
};

export default SecurityPlatformAnalysis;
