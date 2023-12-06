import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import AttackPatternEditionOverview from './AttackPatternEditionOverview';
import AttackPatternEditionDetails from './AttackPatternEditionDetails';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { useFormatter } from '../../../../components/i18n';
import Drawer from '../../common/drawer/Drawer';
import AttackPatternDelete from './AttackPatternDelete';

const AttackPatternEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const { handleClose, attackPattern, open, controlledDial } = props;
  const { editContext } = attackPattern;

  const [currentTab, setCurrentTab] = useState(0);

  const handleChangeTab = (event, value) => setCurrentTab(value);

  return (
    <Drawer
      title={t_i18n('Update an attack pattern')}
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
        {!useIsEnforceReference('Attack-Pattern')
          && <AttackPatternDelete id={attackPattern.id} />
        }
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
