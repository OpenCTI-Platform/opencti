import React from 'react';
import PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';

const SystemAnalysisComponent = (props) => {
  const { system, viewAs } = props;
  return (
    <>
      {viewAs === 'knowledge' ? (
        <StixCoreObjectOrStixCoreRelationshipContainers
          stixDomainObjectOrStixCoreRelationship={system}
          viewAs={viewAs}
        />
      ) : (
        <StixCoreObjectOrStixCoreRelationshipContainers
          stixDomainObjectOrStixCoreRelationship={system}
          authorId={system.id}
          viewAs={viewAs}
        />
      )}
    </>
  );
};

SystemAnalysisComponent.propTypes = {
  system: PropTypes.object,
  classes: PropTypes.object,
  viewAs: PropTypes.string,
};

const SystemAnalysis = createFragmentContainer(SystemAnalysisComponent, {
  system: graphql`
    fragment SystemAnalysis_system on System {
      id
      name
      x_opencti_aliases
      x_opencti_graph_data
    }
  `,
});

export default SystemAnalysis;
