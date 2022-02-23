import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import SystemPopover from './SystemPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';

const styles = () => ({
  container: {
    margin: 0,
    padding: 0,
  },
});

class SystemAnalysisComponent extends Component {
  render() {
    const { classes, system, viewAs, onViewAs } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={system}
          PopoverComponent={<SystemPopover />}
          onViewAs={onViewAs.bind(this)}
          viewAs={viewAs}
        />
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
      </div>
    );
  }
}

SystemAnalysisComponent.propTypes = {
  system: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  viewAs: PropTypes.string,
  onViewAs: PropTypes.func,
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

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(SystemAnalysis);
