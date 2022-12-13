import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import { CaseDetails_case$data, CaseDetails_case$key } from './__generated__/CaseDetails_case.graphql';
import ItemStatus from '../../../../components/ItemStatus';
import ItemCreator from '../../../../components/ItemCreator';

const styles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
}));

const CaseDetailsFragment = graphql`
  fragment CaseDetails_case on Case {
    id
    name
    description
    rating
    created
    modified
    created_at
    creator {
      id
      name
    }
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
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
  }
`;

interface CaseDetailsProps {
  caseData: CaseDetails_case$key,
}

const CaseDetails: FunctionComponent<CaseDetailsProps> = ({ caseData }) => {
  const { t, fldt } = useFormatter();
  const classes = styles();

  const data: CaseDetails_case$data = useFragment(CaseDetailsFragment, caseData);

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Description')}
            </Typography>
            {data.description && (
              <ExpandableMarkdown
                source={data.description}
                limit={300}
              />
            )}
          </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Rating')}
              </Typography>
              {data.rating}
            </Grid>
            <Grid item={true} xs={6}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Processing status')}
            </Typography>
            <ItemStatus
              status={data?.status}
              disabled={!data?.workflowEnabled}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Creation date')}
            </Typography>
            {fldt(data.created)}
          </Grid>
            <Grid item={true} xs={6}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Modification date')}
            </Typography>
            {fldt(data.modified)}
          </Grid>
          <Grid item={true} xs={6}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t('Creation date (in this platform)')}
            </Typography>
            {fldt(data.created_at)}
          </Grid>
          <Grid item={true} xs={6}>
            <Typography
                variant="h3"
                gutterBottom={true}
              >
                {t('Creator')}
              </Typography>
              <ItemCreator creator={data.creator} />
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};
export default CaseDetails;
