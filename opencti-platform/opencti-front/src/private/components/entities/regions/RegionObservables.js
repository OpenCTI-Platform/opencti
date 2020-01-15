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
import StixRelation from '../../common/stix_relations/StixRelation';
import EntityStixObservables from '../../signatures/stix_observables/EntityStixObservables';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';

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
        <StixDomainEntityHeader
          stixDomainEntity={region}
          PopoverComponent={<RegionPopover />}
        />
        <Route
          exact
          path="/dashboard/entities/regions/:regionId/observables/relations/:relationId"
          render={(routeProps) => (
            <StixRelation
              entityId={region.id}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/regions/:regionId/observables"
          render={(routeProps) => (
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <EntityStixObservables
                entityId={region.id}
                relationType="localization"
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

const RegionObservables = createFragmentContainer(
  RegionObservablesComponent,
  {
    region: graphql`
      fragment RegionObservables_region on Region {
        id
        name
        alias
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(RegionObservables);
