import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';

class IndividualAnalysisComponent extends Component {
  render() {
    const { individual, viewAs } = this.props;
    return (
      <>
        {viewAs === 'knowledge' ? (
          <StixCoreObjectOrStixCoreRelationshipContainers
            stixDomainObjectOrStixCoreRelationship={individual}
            viewAs={viewAs}
          />
        ) : (
          <StixCoreObjectOrStixCoreRelationshipContainers
            authorId={individual.id}
            viewAs={viewAs}
          />
        )}
      </>
    );
  }
}

IndividualAnalysisComponent.propTypes = {
  individual: PropTypes.object,
  viewAs: PropTypes.string,
};

const IndividualAnalysis = createFragmentContainer(
  IndividualAnalysisComponent,
  {
    individual: graphql`
      fragment IndividualAnalysis_individual on Individual {
        id
        name
        x_opencti_aliases
        x_opencti_graph_data
      }
    `,
  },
);

export default withRouter(IndividualAnalysis);
