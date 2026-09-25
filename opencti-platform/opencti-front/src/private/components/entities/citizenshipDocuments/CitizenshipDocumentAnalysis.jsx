import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';

class CitizenshipDocumentAnalysisComponent extends Component {
  render() {
    const { citizenshipDocument, viewAs } = this.props;
    return (
      <>
        {viewAs === 'knowledge' ? (
          <StixCoreObjectOrStixCoreRelationshipContainers
            stixDomainObjectOrStixCoreRelationship={citizenshipDocument}
            viewAs={viewAs}
          />
        ) : (
          <StixCoreObjectOrStixCoreRelationshipContainers
            stixDomainObjectOrStixCoreRelationship={citizenshipDocument}
            authorId={citizenshipDocument.id}
            viewAs={viewAs}
          />
        )}
      </>
    );
  }
}

CitizenshipDocumentAnalysisComponent.propTypes = {
  citizenshipDocument: PropTypes.object,
  viewAs: PropTypes.string,
};

const CitizenshipDocumentAnalysis = createFragmentContainer(
  CitizenshipDocumentAnalysisComponent,
  {
    citizenshipDocument: graphql`
      fragment CitizenshipDocumentAnalysis_citizenshipDocument on CitizenshipDocument {
        id
        name
        x_opencti_aliases
        x_opencti_graph_data
      }
    `,
  },
);

export default CitizenshipDocumentAnalysis;
