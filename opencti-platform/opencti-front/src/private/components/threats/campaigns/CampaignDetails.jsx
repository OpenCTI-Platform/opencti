import React from 'react';
import PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import MarkdownDisplay from '../../../../components/markdownDisplay/MarkdownDisplay';
import Card from '@common/card/Card';
import Label from '../../../../components/common/label/Label';

const CampaignDetailsComponent = (props) => {
  const { fldt, t_i18n } = useFormatter();
  const { campaign } = props;
  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={12}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown source={campaign.description} limit={400} />
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Objective')}
            </Label>
            <MarkdownDisplay
              content={campaign.objective}
              remarkGfmPlugin={true}
              commonmark={true}
            />
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('First seen')}
            </Label>
            {fldt(campaign.first_seen)}
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Last seen')}
            </Label>
            {fldt(campaign.last_seen)}
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};

CampaignDetailsComponent.propTypes = {
  campaign: PropTypes.object,
};

const CampaignDetails = createFragmentContainer(CampaignDetailsComponent, {
  campaign: graphql`
    fragment CampaignDetails_campaign on Campaign {
      id
      description
      first_seen
      last_seen
      objective
    }
  `,
});

export default CampaignDetails;
