import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import { FeedbackDetails_case$data, FeedbackDetails_case$key } from './__generated__/FeedbackDetails_case.graphql';
import RatingField from '../../../../components/fields/RatingField';
import Card from '../../../../components/common/card/Card';

const FeedbackDetailsFragment = graphql`
  fragment FeedbackDetails_case on Feedback {
    id
    name
    description
    rating
    created
    modified
    created_at
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
  }
`;

interface FeedbackDetailsProps {
  feedbackData: FeedbackDetails_case$key;
}

const FeedbackDetails: FunctionComponent<FeedbackDetailsProps> = ({
  feedbackData,
}) => {
  const { t_i18n } = useFormatter();
  const data: FeedbackDetails_case$data = useFragment(
    FeedbackDetailsFragment,
    feedbackData,
  );
  return (
    <div style={{ height: '100%' }} data-testid="feedback-details-page">
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Rating')}
            </Typography>
            <RatingField rating={data.rating} size="small" readOnly={true} />
          </Grid>
          <Grid item xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Description')}
            </Typography>
            {data.description && (
              <ExpandableMarkdown source={data.description} limit={300} />
            )}
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};
export default FeedbackDetails;
