import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Route, withRouter } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import RegionPopover from './RegionPopover';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import EntityStixCyberObservables from '../../observations/stix_cyber_observables/StixCoreObjectStixCyberObservables';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
  containerWithoutPadding: {
    margin: 0,
    padding: 0,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '5px 0 40px 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class RegionObservablesComponent extends Component {
  render() {
    const { classes, region, location } = this.props;
    const link = `/dashboard/entities/regions/${region.id}/observables`;
    return (
      <div
        className={
          location.pathname.includes(
            `/dashboard/entities/regions/${region.id}/observables/relations/`,
          )
            ? classes.containerWithoutPadding
            : classes.container
        }
      >
        <StixDomainObjectHeader
          stixDomainObject={region}
          PopoverComponent={<RegionPopover />}
        />
        <Route
          exact
          path="/dashboard/entities/regions/:regionId/observables/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship entityId={region.id} {...routeProps} />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/regions/:regionId/observables"
          render={(routeProps) => (
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <EntityStixCyberObservables
                entityId={region.id}
                relationshipType="localization"
                entityLink={link}
                {...routeProps}
              />
            </Paper>
          )}
        />
      </div>
    );
  }
}

RegionObservablesComponent.propTypes = {
  region: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const RegionObservables = createFragmentContainer(RegionObservablesComponent, {
  region: graphql`
    fragment RegionObservables_region on Region {
      id
      name
      x_opencti_aliases
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(RegionObservables);
