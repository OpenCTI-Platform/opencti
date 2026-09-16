import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import CampaignEditionOverview from './CampaignEditionOverview';
import CampaignEditionDetails from './CampaignEditionDetails';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';

const CampaignEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const [currentTab, setCurrentTab] = useState('overview');
  const enableReferences = useIsEnforceReference('Campaign');

  const { handleClose, campaign, open, controlledDial } = props;
  const { editContext } = campaign;
  return (
    <Drawer
      title={t_i18n('Update a campaign')}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
    >
      <Tabs value={currentTab} onValueChange={setCurrentTab}>
        <TabsList>
          <TabsTrigger value="overview">{t_i18n('Overview')}</TabsTrigger>
          <TabsTrigger value="details">{t_i18n('Details')}</TabsTrigger>
        </TabsList>
        <TabsContent value="overview">
          <CampaignEditionOverview
            campaign={campaign}
            enableReferences={enableReferences}
            context={editContext}
            handleClose={handleClose}
          />
        </TabsContent>
        <TabsContent value="details">
          <CampaignEditionDetails
            campaign={campaign}
            enableReferences={enableReferences}
            context={editContext}
            handleClose={handleClose}
          />
        </TabsContent>
      </Tabs>
    </Drawer>
  );
};

const CampaignEditionFragment = createFragmentContainer(
  CampaignEditionContainer,
  {
    campaign: graphql`
      fragment CampaignEditionContainer_campaign on Campaign {
        id
        ...CampaignEditionOverview_campaign
        ...CampaignEditionDetails_campaign
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default CampaignEditionFragment;
