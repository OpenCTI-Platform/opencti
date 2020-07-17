import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Route, withRouter } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import XOpenctiIncidentPopover from './XOpenctiXOpenctiIncidentPopover';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import EntityStixCyberObservables from '../../signatures/stix_cyber_observables/EntityStixCyberObservables';
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

class XOpenctiIncidentObservablesComponent extends Component {
  render() {
    const { classes, xOpenctiIncident, location } = this.props;
    const link = `/dashboard/threats/xOpenctiIncidents/${xOpenctiIncident.id}/observables`;
    return (
      <div
        className={
          location.pathname.includes(
            `/dashboard/threats/xOpenctiIncidents/${xOpenctiIncident.id}/observables/relations/`,
          )
            ? classes.containerWithoutPadding
            : classes.container
        }
      >
        <StixDomainObjectHeader
          stixDomainObject={xOpenctiIncident}
          PopoverComponent={<XOpenctiIncidentPopover />}
        />
        <Route
          exact
          path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId/observables/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship entityId={xOpenctiIncident.id} {...routeProps} />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId/observables"
          render={(routeProps) => (
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <EntityStixCyberObservables
                entityId={xOpenctiIncident.id}
                relationType="related-to"
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

XOpenctiIncidentObservablesComponent.propTypes = {
  xOpenctiIncident: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const XOpenctiIncidentObservables = createFragmentContainer(
  XOpenctiIncidentObservablesComponent,
  {
    xOpenctiIncident: graphql`
      fragment XOpenctiIncidentObservables_xOpenctiIncident on XOpenctiIncident {
        id
        name
        aliases
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(XOpenctiIncidentObservables);
