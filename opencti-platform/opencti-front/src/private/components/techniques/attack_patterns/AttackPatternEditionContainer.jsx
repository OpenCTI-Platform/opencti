import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import AttackPatternEditionOverview from './AttackPatternEditionOverview';
import AttackPatternEditionDetails from './AttackPatternEditionDetails';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { useFormatter } from '../../../../components/i18n';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const AttackPatternEditionContainer = (props) => {
  const { t } = useFormatter();

  const { handleClose, attackPattern, open } = props;
  const { editContext } = attackPattern;

  const [currentTab, setCurrentTab] = useState(0);

  const handleChangeTab = (event, value) => setCurrentTab(value);

  return (
    <Drawer
      title={t('Update an attack pattern')}
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
          <AttackPatternEditionOverview
            attackPattern={attackPattern}
            enableReferences={useIsEnforceReference('Attack-Pattern')}
            context={editContext}
            handleClose={handleClose}
          />
        )}
        {currentTab === 1 && (
          <AttackPatternEditionDetails
            attackPattern={attackPattern}
            enableReferences={useIsEnforceReference('Attack-Pattern')}
            context={editContext}
            handleClose={handleClose}
          />
        )}
      </>
    </Drawer>
  );
};

const AttackPatternEditionFragment = createFragmentContainer(
  AttackPatternEditionContainer,
  {
    attackPattern: graphql`
      fragment AttackPatternEditionContainer_attackPattern on AttackPattern {
        id
        ...AttackPatternEditionOverview_attackPattern
        ...AttackPatternEditionDetails_attackPattern
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default AttackPatternEditionFragment;
