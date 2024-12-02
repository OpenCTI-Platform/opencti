import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import RelatedContainers from '@components/common/containers/RelatedContainers';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import type { Theme } from '../../../../components/Theme';
import { CaseIncidentDetails_case$key } from './__generated__/CaseIncidentDetails_case.graphql';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
    position: 'relative',
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
}));

const CaseIncidentDetailsFragment = graphql`
  fragment CaseIncidentDetails_case on CaseIncident {
    id
    name
    entity_type
    description
    priority
    severity
    created
    modified
    created_at
    response_types
    objectLabel {
      id
      value
      color
    }
    name
    x_opencti_stix_ids
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    relatedContainers(
      first: 10
      orderBy: created
      orderMode: desc
      types: ["Case", "Report", "Grouping"]
      viaTypes: ["Indicator", "Stix-Cyber-Observable"]
    ) {
      ...RelatedContainersFragment_container_connection
    }
  }
`;

interface CaseIncidentDetailsProps {
  caseIncidentData: CaseIncidentDetails_case$key;
}

const CaseIncidentDetails: FunctionComponent<CaseIncidentDetailsProps> = ({
  caseIncidentData,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const data = useFragment(CaseIncidentDetailsFragment, caseIncidentData);
  const responseTypes = data.response_types ?? [];

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
        <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Priority')}
            </Typography>
            <ItemOpenVocab
              key="type"
              small={true}
              type="case_priority_ov"
              value={data.priority}
              displayMode="chip"
            />
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Severity')}
            </Typography>
            <ItemOpenVocab
              key="type"
              small={true}
              type="case_severity_ov"
              value={data.severity}
              displayMode="chip"
            />
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Incident response type')}
            </Typography>
            {responseTypes.length > 0
              ? (data.response_types ?? []).map((responseType) => (
                <Chip
                  key={responseType}
                  classes={{ root: classes.chip }}
                  label={responseType}
                />
              ))
              : '-'}
          </Grid>
          <Grid item xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Description')}
            </Typography>
            {data.description ? (
              <ExpandableMarkdown source={data.description} limit={300} />
            ) : (
              '-'
            )}
          </Grid>
        </Grid>
        <RelatedContainers
          relatedContainers={data.relatedContainers}
          containerId={data.id}
          entityType={data.entity_type}
        />
      </Paper>
    </div>
  );
};
export default CaseIncidentDetails;
