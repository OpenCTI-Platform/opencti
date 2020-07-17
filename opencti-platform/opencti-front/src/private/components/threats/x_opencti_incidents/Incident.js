import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import IncidentOverview from './IncidentOverview';
import IncidentDetails from './IncidentDetails';
import IncidentEdition from './IncidentEdition';
import IncidentPopover from './IncidentPopover';
import EntityLastReports from '../../reports/EntityLastReports';
import EntityReportsChart from '../../reports/EntityReportsChart';
import EntityStixCoreRelationshipsDonut from '../../common/stix_core_relationships/EntityStixCoreRelationshipsDonut';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectNotes from '../../common/stix_core_object/StixCoreObjectNotes';

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
        <StixDomainObjectHeader
          stixDomainObject={incident}
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
            <IncidentDetails incident={incident} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={incident.id} />
          </Grid>
        </Grid>
        <StixCoreObjectNotes entityId={incident.id} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 15 }}
        >
          <Grid item={true} xs={6}>
            <EntityStixCoreRelationshipsDonut
              entityId={incident.id}
              entityType="Stix-Observable"
              relationType="related-to"
              field="entity_type"
            />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityReportsChart entityId={incident.id} />
          </Grid>
        </Grid>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <IncidentEdition incidentId={incident.id} />
        </Security>
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
      aliases
      ...IncidentOverview_incident
      ...IncidentDetails_incident
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Incident);
