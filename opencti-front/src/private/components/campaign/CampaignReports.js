import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import CampaignHeader from './CampaignHeader';
import EntityReports from '../report/EntityReports';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class CampaignReportsComponent extends Component {
  render() {
    const { classes, campaign } = this.props;
    return (
      <div className={classes.container}>
        <CampaignHeader campaign={campaign}/>
        <div style={{ height: 20 }}/>
        <EntityReports entityId={campaign.id}/>
      </div>
    );
  }
}

CampaignReportsComponent.propTypes = {
  campaign: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const CampaignReports = createFragmentContainer(CampaignReportsComponent, {
  campaign: graphql`
      fragment CampaignReports_campaign on Campaign {
          id
          ...CampaignHeader_campaign
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(CampaignReports);
