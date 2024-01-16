import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { useFormatter } from '../../../../components/i18n';
import ThreatActorGroupEditionOverview from './ThreatActorGroupEditionOverview';
import ThreatActorGroupEditionDetails from './ThreatActorGroupEditionDetails';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const ThreatActorGroupEditionContainer = ({
  handleClose,
  threatActorGroup,
  open,
}) => {
  const { t_i18n } = useFormatter();
  const { editContext } = threatActorGroup;
  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (event, value) => setCurrentTab(value);
  return (
    <Drawer
      title={t_i18n('Update a threat actor group')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
    >
      <>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={currentTab} onChange={handleChangeTab}>
            <Tab label={t_i18n('Overview')} />
            <Tab label={t_i18n('Details')} />
          </Tabs>
        </Box>
        {currentTab === 0 && (
          <ThreatActorGroupEditionOverview
            threatActorGroup={threatActorGroup}
            enableReferences={useIsEnforceReference('Threat-Actor-Group')}
            context={editContext}
            handleClose={handleClose}
          />
        )}
        {currentTab === 1 && (
          <ThreatActorGroupEditionDetails
            threatActorGroup={threatActorGroup}
            enableReferences={useIsEnforceReference('Threat-Actor-Group')}
            context={editContext}
            handleClose={handleClose}
          />
        )}
      </>
    </Drawer>
  );
};

const ThreatActorGroupEditionFragment = createFragmentContainer(
  ThreatActorGroupEditionContainer,
  {
    threatActorGroup: graphql`
      fragment ThreatActorGroupEditionContainer_ThreatActorGroup on ThreatActorGroup {
        id
        ...ThreatActorGroupEditionOverview_ThreatActorGroup
        ...ThreatActorGroupEditionDetails_ThreatActorGroup
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default ThreatActorGroupEditionFragment;
