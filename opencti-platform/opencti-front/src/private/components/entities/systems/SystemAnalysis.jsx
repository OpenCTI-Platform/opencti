import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import inject18n from '../../../../components/i18n';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';

class SystemAnalysisComponent extends Component {
  render() {
    const { system, viewAs } = this.props;
    return (
      <>
        {viewAs === 'knowledge' ? (
          <StixCoreObjectOrStixCoreRelationshipContainers
            stixDomainObjectOrStixCoreRelationship={system}
            viewAs={viewAs}
          />
        ) : (
          <StixCoreObjectOrStixCoreRelationshipContainers
            authorId={system.id}
            viewAs={viewAs}
          />
        )}
      </>
    );
  }
}

SystemAnalysisComponent.propTypes = {
  system: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
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

export default R.compose(inject18n, withRouter)(SystemAnalysis);
