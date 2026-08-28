import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import CampaignEditionContainer from './CampaignEditionContainer';
import { campaignEditionOverviewFocus } from './CampaignEditionOverview';
import Loader from '../../../../components/Loader';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

export const campaignEditionQuery = graphql`
  query CampaignEditionContainerQuery($id: String!) {
    campaign(id: $id) {
      ...CampaignEditionContainer_campaign
    }
  }
`;

const CampaignEdition = (props) => {
  const handleClose = () => {
    commitMutation({
      mutation: campaignEditionOverviewFocus,
      variables: {
        id: props.campaignId,
        input: { focusOn: '' },
      },
    });
  };

  const { campaignId } = props;
  return (
    <QueryRenderer
      query={campaignEditionQuery}
      variables={{ id: campaignId }}
      render={({ props }) => {
        if (props) {
          return (
            <CampaignEditionContainer
              campaign={props.campaign}
              handleClose={handleClose}
              controlledDial={EditEntityControlledDial}
            />
          );
        }
        return <Loader variant="inline" />;
      }}
    />
  );
};

CampaignEdition.propTypes = {
  campaignId: PropTypes.string,
  theme: PropTypes.object,
};

export default CampaignEdition;
