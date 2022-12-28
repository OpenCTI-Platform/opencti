import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import { CaseDetails_case$data, CaseDetails_case$key } from './__generated__/CaseDetails_case.graphql';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import { IconContainer, StyledRating } from './FeedbackCreation';

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
    type
    priority
    severity
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
  const { t } = useFormatter();
  const classes = styles();

  const data: CaseDetails_case$data = useFragment(CaseDetailsFragment, caseData);

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>{t('Type')}</Typography>
            <ItemOpenVocab key="type" small={true} type="case_types_ov" value={data.type} />
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>{t('Rating')}</Typography>
            <StyledRating
              name='highlight-selected-only'
              value={data.rating}
              IconContainerComponent={IconContainer}
              highlightSelectedOnly
              readOnly
            />
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>{t('Priority')}</Typography>
            <ItemOpenVocab key="type" small={true} type="case_priority_ov" value={data.priority} />
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>{t('Severity')}</Typography>
            <ItemOpenVocab key="type" small={true} type="case_severity_ov" value={data.severity} />
          </Grid>
          <Grid item={true} xs={12}>
            <Typography variant="h3" gutterBottom={true}>{t('Description')}</Typography>
            {data.description && (<ExpandableMarkdown source={data.description} limit={300} />)}
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};
export default CaseDetails;
