import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import OrganizationPopover from './OrganizationPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';

const styles = () => ({
  container: {
    margin: 0,
    padding: 0,
  },
});

class OrganizationAnalysisComponent extends Component {
  render() {
    const { classes, organization, viewAs, onViewAs } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={organization}
          PopoverComponent={<OrganizationPopover />}
          onViewAs={onViewAs.bind(this)}
          viewAs={viewAs}
        />
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
      </div>
    );
  }
}

OrganizationAnalysisComponent.propTypes = {
  organization: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  viewAs: PropTypes.string,
  onViewAs: PropTypes.func,
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

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(OrganizationAnalysis);
