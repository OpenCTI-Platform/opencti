import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';

class SecurityPlatformAnalysisComponent extends Component {
  render() {
    const { securityPlatform, viewAs } = this.props;
    console.log('securityPlatform', securityPlatform);
    return (
      <>
        {viewAs === 'knowledge' ? (
          <StixCoreObjectOrStixCoreRelationshipContainers
            stixDomainObjectOrStixCoreRelationship={securityPlatform}
            viewAs={viewAs}
          />
        ) : (
          <StixCoreObjectOrStixCoreRelationshipContainers
            stixDomainObjectOrStixCoreRelationship={securityPlatform}
            authorId={securityPlatform.id}
            viewAs={viewAs}
          />
        )}
      </>
    );
  }
}

SecurityPlatformAnalysisComponent.propTypes = {
  securityPlatform: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  viewAs: PropTypes.string,
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
