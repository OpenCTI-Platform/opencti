import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import IndividualPopover from './IndividualPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';

const styles = () => ({
  container: {
    margin: 0,
    padding: 0,
  },
});

class IndividualAnalysisComponent extends Component {
  render() {
    const { classes, individual, viewAs, onViewAs } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={individual}
          PopoverComponent={<IndividualPopover />}
          onViewAs={onViewAs.bind(this)}
          viewAs={viewAs}
        />
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
      </div>
    );
  }
}

IndividualAnalysisComponent.propTypes = {
  individual: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  viewAs: PropTypes.string,
  onViewAs: PropTypes.func,
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

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(IndividualAnalysis);
