import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { useFormatter } from '../../../../components/i18n';
import CampaignEditionOverview from './CampaignEditionOverview';
import CampaignEditionDetails from './CampaignEditionDetails';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';
import CampaignDelete from './CampaignDelete';

const CampaignEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (event, value) => setCurrentTab(value);

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
      <>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={currentTab} onChange={handleChangeTab}>
            <Tab label={t_i18n('Overview')} />
            <Tab label={t_i18n('Details')} />
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
        {!useIsEnforceReference('Campaign')
          && <CampaignDelete id={campaign.id} />
        }
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
