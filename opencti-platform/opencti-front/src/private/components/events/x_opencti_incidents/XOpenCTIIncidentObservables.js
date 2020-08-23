import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Route, withRouter } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import XOpenCTIIncidentPopover from './XOpenCTIIncidentPopover';
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

class XOpenCTIIncidentObservablesComponent extends Component {
  render() {
    const { classes, XOpenCTIIncident, location } = this.props;
    const link = `/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncident.id}/observables`;
    return (
      <div
        className={
          location.pathname.includes(
            `/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncident.id}/observables/relations/`,
          )
            ? classes.containerWithoutPadding
            : classes.container
        }
      >
        <StixDomainObjectHeader
          stixDomainObject={XOpenCTIIncident}
          PopoverComponent={<XOpenCTIIncidentPopover />}
        />
        <Route
          exact
          path="/dashboard/threats/XOpenCTIIncidents/:XOpenCTIIncidentId/observables/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship
              entityId={XOpenCTIIncident.id}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/XOpenCTIIncidents/:XOpenCTIIncidentId/observables"
          render={(routeProps) => (
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <EntityStixCyberObservables
                entityId={XOpenCTIIncident.id}
                relationshipType="related-to"
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

XOpenCTIIncidentObservablesComponent.propTypes = {
  XOpenCTIIncident: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const XOpenCTIIncidentObservables = createFragmentContainer(
  XOpenCTIIncidentObservablesComponent,
  {
    xOpenCTIIncident: graphql`
      fragment XOpenCTIIncidentObservables_xOpenCTIIncident on XOpenCTIIncident {
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
)(XOpenCTIIncidentObservables);
