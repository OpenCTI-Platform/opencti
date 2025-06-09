import React, { FunctionComponent } from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import { SecurityPlatformAnalysis_securityPlatform$key } from '@components/entities/securityPlatforms/__generated__/SecurityPlatformAnalysis_securityPlatform.graphql';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';

interface SecurityPlatformAnalysisComponentProps {
  securityPlatform: SecurityPlatformAnalysis_securityPlatform$key;
}

const SecurityPlatformAnalysisComponent: FunctionComponent<SecurityPlatformAnalysisComponentProps> = ({ securityPlatform }) => {
  return (
    <StixCoreObjectOrStixCoreRelationshipContainers
      stixDomainObjectOrStixCoreRelationship={securityPlatform}
    />
  );
};

const SecurityPlatformAnalysis = createFragmentContainer(
  SecurityPlatformAnalysisComponent,
  {
    securityPlatform: graphql`
      fragment SecurityPlatformAnalysis_securityPlatform on SecurityPlatform {
        id
        name
        x_opencti_aliases
        x_opencti_graph_data
      }
    `,
  },
);

export default SecurityPlatformAnalysis;
