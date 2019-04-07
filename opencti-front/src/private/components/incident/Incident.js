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
import IncidentIdentity from './IncidentIdentity';
import IncidentEdition from './IncidentEdition';
import EntityLastReports from '../report/EntityLastReports';
import EntityReportsChart from '../report/EntityReportsChart';
import EntityStixRelationsRadar from '../stix_relation/EntityStixRelationsRadar';
import EntityStixRelationsDonut from '../stix_relation/EntityStixRelationsDonut';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class IncidentComponent extends Component {
  render() {
    const { classes, incident } = this.props;
    return (
      <div className={classes.container}>
        <IncidentHeader incident={incident} />
        <Grid
          container={true}
          spacing={32}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={3}>
            <IncidentOverview incident={incident} />
          </Grid>
          <Grid item={true} xs={3}>
            <IncidentIdentity incident={incident} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={incident.id} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={32}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 20 }}
        >
          <Grid item={true} xs={4}>
            <EntityStixRelationsRadar
              entityId={incident.id}
              entityType="Kill-Chain-Phase"
              relationType="kill_chain_phases"
              field="phase_name"
              resolveInferences={true}
              resolveRelationType="uses"
              resolveRelationRole="user"
            />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityStixRelationsDonut
              entityId={incident.id}
              entityType="Stix-Observable"
              relationType="indicates"
              field="entity_type"
            />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={incident.id} />
          </Grid>
        </Grid>
        <IncidentEdition incidentId={incident.id} />
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
      ...IncidentIdentity_incident
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(Incident);
