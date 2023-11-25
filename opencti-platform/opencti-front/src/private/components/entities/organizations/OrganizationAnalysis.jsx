import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';

class OrganizationAnalysisComponent extends Component {
  render() {
    const { organization, viewAs } = this.props;
    return (
      <>
        {viewAs === 'knowledge' ? (
          <StixCoreObjectOrStixCoreRelationshipContainers
            stixDomainObjectOrStixCoreRelationship={organization}
            viewAs={viewAs}
          />
        ) : (
          <StixCoreObjectOrStixCoreRelationshipContainers
            authorId={organization.id}
            viewAs={viewAs}
          />
        )}
      </>
    );
  }
}

OrganizationAnalysisComponent.propTypes = {
  organization: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  viewAs: PropTypes.string,
};

const OrganizationAnalysis = createFragmentContainer(
  OrganizationAnalysisComponent,
  {
    organization: graphql`
      fragment OrganizationAnalysis_organization on Organization {
        id
        name
        x_opencti_aliases
        x_opencti_graph_data
      }
    `,
  },
);

export default withRouter(OrganizationAnalysis);
