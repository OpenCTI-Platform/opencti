import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Route, withRouter } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import ThreatActorPopover from './ThreatActorPopover';
import StixRelation from '../../common/stix_relations/StixRelation';
import EntityIndicators from '../../signatures/indicators/EntityIndicators';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';

const styles = () => ({
  container: {
    margin: 0,
  },
  containerWithoutPadding: {
    margin: 0,
    padding: 0,
  },
  paper: {
    minHeight: '100%',
    margin: '5px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class ThreatActorIndicatorsComponent extends Component {
  render() {
    const { classes, threatActor, location } = this.props;
    const link = `/dashboard/threats/threat_actors/${threatActor.id}/indicators`;
    return (
      <div
        className={
          location.pathname.includes(
            `/dashboard/threats/threat_actors/${threatActor.id}/indicators/relations/`,
          )
            ? classes.containerWithoutPadding
            : classes.container
        }>
        <StixDomainEntityHeader
          stixDomainEntity={threatActor}
          PopoverComponent={<ThreatActorPopover />}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors/:threatActorId/indicators/relations/:relationId"
          render={(routeProps) => (
            <StixRelation
              entityId={threatActor.id}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/threat_actors/:threatActorId/indicators"
          render={(routeProps) => (
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <EntityIndicators
                entityId={threatActor.id}
                relationType="indicates"
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

ThreatActorIndicatorsComponent.propTypes = {
  threatActor: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ThreatActorIndicators = createFragmentContainer(
  ThreatActorIndicatorsComponent,
  {
    threatActor: graphql`
      fragment ThreatActorIndicators_threatActor on ThreatActor {
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
)(ThreatActorIndicators);
