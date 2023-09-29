import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { useFormatter } from '../../../../components/i18n';
import CampaignEditionOverview from './CampaignEditionOverview';
import CampaignEditionDetails from './CampaignEditionDetails';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const CampaignEditionContainer = (props) => {
  const { t } = useFormatter();

  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (event, value) => setCurrentTab(value);

  const { handleClose, campaign, open } = props;
  const { editContext } = campaign;
  return (
    <Drawer
      title={t('Update a campaign')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
    >
      <>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={currentTab} onChange={handleChangeTab}>
            <Tab label={t('Overview')} />
            <Tab label={t('Details')} />
          </Tabs>
        </Box>
        {currentTab === 0 && (
          <CampaignEditionOverview
            campaign={campaign}
            enableReferences={useIsEnforceReference('Campaign')}
            context={editContext}
            handleClose={handleClose}
          />
        )}
        {currentTab === 1 && (
          <CampaignEditionDetails
            campaign={campaign}
            enableReferences={useIsEnforceReference('Campaign')}
            context={editContext}
            handleClose={handleClose}
          />
        )}
      </>
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
