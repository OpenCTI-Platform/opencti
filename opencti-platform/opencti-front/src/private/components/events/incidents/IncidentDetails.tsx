import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import { makeStyles } from '@mui/styles';
import Chip from '@mui/material/Chip';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { Theme } from '../../../../components/Theme';
import {
  IncidentDetails_incident$data,
  IncidentDetails_incident$key,
} from './__generated__/IncidentDetails_incident.graphql';
import StixCoreObjectsDonut from '../../common/stix_core_objects/StixCoreObjectsDonut';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';

const useStyles = makeStyles<Theme>(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  chip: {
    fontSize: 12,
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: '0',
    width: 120,
  },
  chip2: {
    fontSize: 12,
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: '0',
    width: 150,
  },
}));

const incidentDetailsFragment = graphql`
  fragment IncidentDetails_incident on Incident {
    id
    first_seen
    last_seen
    objective
    description
    incident_type
    severity
    source
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    is_inferred
  }
`;

interface IncidentDetailsProps {
  incidentData: IncidentDetails_incident$key;
}
const IncidentDetails: FunctionComponent<IncidentDetailsProps> = ({
  incidentData,
}) => {
  const classes = useStyles();
  const { t, fldt } = useFormatter();

  const incident: IncidentDetails_incident$data = useFragment(
    incidentDetailsFragment,
    incidentData,
  );

  const entitiesDataSelection = [
    {
      attribute: 'entity_type',
      filters: {
        entity_type: [{ id: 'Stix-Domain-Object' }],
        elementId: [{ id: incident.id }],
        relationship_type: [{ id: 'related-to' }],
      },
    },
  ];
  const observablesDataSelection = [
    {
      attribute: 'entity_type',
      filters: {
        entity_type: [{ id: 'Stix-Cyber-Observable' }],
        elementId: [{ id: incident.id }],
        relationship_type: [{ id: 'related-to' }],
      },
    },
  ];
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Incident type')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
              color="primary"
              variant="outlined"
              label={incident.incident_type || t('Unknown')}
            />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('First seen')}
            </Typography>
            {fldt(incident.first_seen)}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Description')}
            </Typography>
            <ExpandableMarkdown source={incident.description} limit={400} />
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Severity')}
            </Typography>
            <ItemOpenVocab
              key="type"
              small={true}
              type="incident_severity_ov"
              value={incident.severity}
            />
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
              {t('Source')}
            </Typography>
            <Chip
              classes={{ root: classes.chip2 }}
              color="secondary"
              variant="outlined"
              label={incident.source || t('Unknown')}
            />
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
            <StixCoreObjectsDonut
              dataSelection={entitiesDataSelection}
              parameters={{ title: t('Entities distribution') }}
              variant="inEntity"
              height={300}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectsDonut
              dataSelection={observablesDataSelection}
              parameters={{ title: t('Observables distribution') }}
              variant="inEntity"
              height={300}
            />
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default IncidentDetails;
