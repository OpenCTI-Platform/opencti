import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import IncidentOverview from './IncidentOverview';
import IncidentIdentity from './IncidentIdentity';
import IncidentEdition from './IncidentEdition';
import IncidentPopover from './IncidentPopover';
import EntityLastReports from '../../reports/EntityLastReports';
import EntityReportsChart from '../../reports/EntityReportsChart';
import EntityStixRelationsRadar from '../../common/stix_relations/EntityStixRelationsRadar';
import EntityStixRelationsDonut from '../../common/stix_relations/EntityStixRelationsDonut';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';

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
        <StixDomainEntityHeader
          stixDomainEntity={incident}
          PopoverComponent={<IncidentPopover />}
        />
        <Grid
          container={true}
          spacing={3}
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
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 30 }}
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
      name
      alias
      ...IncidentOverview_incident
      ...IncidentIdentity_incident
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(Incident);
