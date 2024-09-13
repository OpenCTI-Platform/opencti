import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import { makeStyles } from '@mui/styles';
import Chip from '@mui/material/Chip';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import type { Theme } from '../../../../components/Theme';
import { IncidentDetails_incident$data, IncidentDetails_incident$key } from './__generated__/IncidentDetails_incident.graphql';
import StixCoreObjectsDonut from '../../common/stix_core_objects/StixCoreObjectsDonut';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 4,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text?.primary,
    textTransform: 'uppercase',
    borderRadius: 4,
    margin: '0 5px 5px 0',
  },
  chip2: {
    fontSize: 12,
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: 4,
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
  const { t_i18n, fldt } = useFormatter();

  const incident: IncidentDetails_incident$data = useFragment(
    incidentDetailsFragment,
    incidentData,
  );

  const entitiesDataSelection = [
    {
      attribute: 'entity_type',
      filters: {
        mode: 'and',
        filters: [
          {
            key: 'entity_type',
            values: ['Stix-Domain-Object'],
          },
          {
            key: 'regardingOf',
            values: [
              { key: 'id', values: [incident.id], operator: 'eq' },
              { key: 'relationship_type', values: ['related-to', 'targets', 'uses', 'attributed-to'] },
            ],
          },
        ],
        filterGroups: [],
      },
    },
  ];
  const observablesDataSelection = [
    {
      attribute: 'entity_type',
      filters: {
        mode: 'and',
        filters: [
          {
            key: 'entity_type',
            values: ['Stix-Cyber-Observable'],
          },
          {
            key: 'regardingOf',
            values: [
              { key: 'id', values: [incident.id], operator: 'eq' },
              { key: 'relationship_type', values: ['related-to'], operator: 'eq' },
            ],
          },
        ],
        filterGroups: [],
      },
    },
  ];
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Incident type')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
              label={incident.incident_type || t_i18n('Unknown')}
            />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('First seen')}
            </Typography>
            {fldt(incident.first_seen)}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Description')}
            </Typography>
            <ExpandableMarkdown source={incident.description} limit={400} />
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Severity')}
            </Typography>
            <ItemOpenVocab
              key="type"
              small={true}
              type="incident_severity_ov"
              value={incident.severity}
              displayMode={'chip'}
            />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Last seen')}
            </Typography>
            {fldt(incident.last_seen)}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Source')}
            </Typography>
            <Chip
              classes={{ root: classes.chip2 }}
              color="secondary"
              variant="outlined"
              label={incident.source || t_i18n('Unknown')}
            />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Objective')}
            </Typography>
            <ExpandableMarkdown source={incident.objective} limit={100} />
          </Grid>
          <Grid item xs={6}>
            <StixCoreObjectsDonut
              dataSelection={entitiesDataSelection}
              parameters={{ title: t_i18n('Entities distribution') }}
              variant="inEntity"
              height={300}
            />
          </Grid>
          <Grid item xs={6}>
            <StixCoreObjectsDonut
              dataSelection={observablesDataSelection}
              parameters={{ title: t_i18n('Observables distribution') }}
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
