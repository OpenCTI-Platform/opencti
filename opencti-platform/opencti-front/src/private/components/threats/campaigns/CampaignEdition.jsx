import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import CampaignEditionContainer from './CampaignEditionContainer';
import { campaignEditionOverviewFocus } from './CampaignEditionOverview';
import Loader from '../../../../components/Loader';

export const campaignEditionQuery = graphql`
  query CampaignEditionContainerQuery($id: String!) {
    campaign(id: $id) {
      ...CampaignEditionContainer_campaign
    }
  }
`;

class CampaignEdition extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    commitMutation({
      mutation: campaignEditionOverviewFocus,
      variables: {
        id: this.props.campaignId,
        input: { focusOn: '' },
      },
    });
    this.setState({ open: false });
  }

  render() {
    const { campaignId } = this.props;
    return (
      <QueryRenderer
        query={campaignEditionQuery}
        variables={{ id: campaignId }}
        render={({ props }) => {
          if (props) {
            return (
              <CampaignEditionContainer
                campaign={props.campaign}
                handleClose={this.handleClose.bind(this)}
              />
            );
          }
          return <Loader variant="inElement" />;
        }}
      />
    );
  }
}

CampaignEdition.propTypes = {
  campaignId: PropTypes.string,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
)(CampaignEdition);
