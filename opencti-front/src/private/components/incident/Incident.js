import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import IncidentHeader from './IncidentHeader';
import IncidentOverview from './IncidentOverview';
import IncidentEdition from './IncidentEdition';
import EntityLastReports from '../report/EntityLastReports';
import EntityObservablesChart from '../observable/EntityObservablesChart';
import EntityReportsChart from '../report/EntityReportsChart';
import EntityKillChainPhasesChart from '../kill_chain_phase/EntityKillChainPhasesChart';
import { requestSubscription } from '../../../relay/environment';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

const subscription = graphql`
    subscription IncidentSubscription($id: ID!) {
        stixDomainEntity(id: $id) {
            ...on Incident {
                ...Incident_incident   
            }
        }
    }
`;

class IncidentComponent extends Component {
  componentDidMount() {
    const sub = requestSubscription({
      subscription,
      variables: {
        id: this.props.incident.id,
      },
    });
    this.setState({
      sub,
    });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  render() {
    const { classes, incident } = this.props;
    return (
      <div className={classes.container}>
        <IncidentHeader incident={incident}/>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }}>
          <Grid item={true} xs={6}>
            <IncidentOverview incident={incident}/>
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={incident.id}/>
          </Grid>
        </Grid>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }} style={{ marginTop: 20 }}>
          <Grid item={true} xs={4}>
            <EntityObservablesChart incident={incident}/>
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart incident={incident}/>
          </Grid>
          <Grid item={true} xs={4}>
            <EntityKillChainPhasesChart incident={incident}/>
          </Grid>
        </Grid>
        <IncidentEdition incidentId={incident.id}/>
      </div>
    );
  }
}

IncidentComponent.propTypes = {
  incident: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Incident = createFragmentContainer(IncidentComponent, {
  incident: graphql`
      fragment Incident_incident on Incident {
          id
          ...IncidentHeader_incident
          ...IncidentOverview_incident
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(Incident);
