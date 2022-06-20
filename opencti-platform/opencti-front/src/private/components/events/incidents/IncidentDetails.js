import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationshipsDonut from '../../common/stix_core_relationships/EntityStixCoreRelationshipsDonut';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class IncidentDetailsComponent extends Component {
  render() {
    const { fldt, t, classes, incident } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Description')}
              </Typography>
              <ExpandableMarkdown source={incident.description} limit={400} />
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('First seen')}
              </Typography>
              {fldt(incident.first_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Last seen')}
              </Typography>
              {fldt(incident.last_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Objective')}
              </Typography>
              <ExpandableMarkdown source={incident.objective} limit={100} />
            </Grid>
            <Grid item={true} xs={6}>
              <EntityStixCoreRelationshipsDonut
                entityId={incident.id}
                toTypes={['Stix-Domain-Object']}
                relationshipType="stix-core-relationship"
                field="entity_type"
                height={260}
                variant="inEntity"
                isTo={false}
                title={t('Entities distribution')}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <EntityStixCoreRelationshipsDonut
                entityId={incident.id}
                toTypes={['Stix-Cyber-Observable']}
                relationshipType="stix-core-relationship"
                field="entity_type"
                height={260}
                variant="inEntity"
                isTo={true}
                title={t('Observables distribution')}
              />
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

IncidentDetailsComponent.propTypes = {
  incident: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const IncidentDetails = createFragmentContainer(IncidentDetailsComponent, {
  incident: graphql`
    fragment IncidentDetails_incident on Incident {
      id
      first_seen
      last_seen
      objective
      description
      status {
        id
        order
        template {
          name
          color
        }
      }
      workflowEnabled
    }
  `,
});

export default compose(inject18n, withStyles(styles))(IncidentDetails);
