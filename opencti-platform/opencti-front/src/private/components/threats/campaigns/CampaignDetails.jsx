import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import Card from '@common/card/Card';
import Label from '../../../../components/common/label/Label';

class CampaignDetailsComponent extends Component {
  render() {
    const { fldt, t, campaign } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Card title={t('Details')}>
          <Grid container={true} spacing={3}>
            <Grid item xs={6}>
              <Label>
                {t('Description')}
              </Label>
              <ExpandableMarkdown source={campaign.description} limit={400} />
              <Label
                sx={{ marginTop: 2 }}
              >
                {t('Objective')}
              </Label>
              <MarkdownDisplay
                content={campaign.objective}
                remarkGfmPlugin={true}
                commonmark={true}
              />
            </Grid>
            <Grid item xs={6}>
              <Label>
                {t('First seen')}
              </Label>
              {fldt(campaign.first_seen)}
              <Label
                sx={{ marginTop: 2 }}
              >
                {t('Last seen')}
              </Label>
              {fldt(campaign.last_seen)}
            </Grid>
          </Grid>
        </Card>
      </div>
    );
  }
}

CampaignDetailsComponent.propTypes = {
  campaign: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
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

export default compose(inject18n)(CampaignDetails);
