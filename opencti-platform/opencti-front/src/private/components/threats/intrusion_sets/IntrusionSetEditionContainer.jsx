import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { useFormatter } from '../../../../components/i18n';
import IntrusionSetEditionOverview from './IntrusionSetEditionOverview';
import IntrusionSetEditionDetails from './IntrusionSetEditionDetails';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import useHelper from '../../../../utils/hooks/useHelper';

const IntrusionSetEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const { handleClose, intrusionSet, open, controlledDial } = props;
  const { editContext } = intrusionSet;

  const [currentTab, setCurrentTab] = useState(0);

  const handleChangeTab = (event, value) => setCurrentTab(value);

  return (
    <Drawer
      title={t_i18n('Update an intrusion set')}
      open={open}
      onClose={handleClose}
      variant={!isFABReplaced && open == null ? DrawerVariant.update : undefined}
      context={editContext}
      controlledDial={isFABReplaced ? controlledDial : undefined}
    >
      <>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={currentTab} onChange={handleChangeTab}>
            <Tab label={t_i18n('Overview')} />
            <Tab label={t_i18n('Details')} />
          </Tabs>
        </Box>
        {currentTab === 0 && (
          <IntrusionSetEditionOverview
            intrusionSet={intrusionSet}
            enableReferences={useIsEnforceReference('Intrusion-Set')}
            context={editContext}
            handleClose={handleClose}
          />
        )}
        {currentTab === 1 && (
          <IntrusionSetEditionDetails
            intrusionSet={intrusionSet}
            enableReferences={useIsEnforceReference('Intrusion-Set')}
            context={editContext}
            handleClose={handleClose}
          />
        )}
      </>
    </Drawer>
  );
};

const IntrusionSetEditionFragment = createFragmentContainer(
  IntrusionSetEditionContainer,
  {
    intrusionSet: graphql`
      fragment IntrusionSetEditionContainer_intrusionSet on IntrusionSet {
        id
        ...IntrusionSetEditionOverview_intrusionSet
        ...IntrusionSetEditionDetails_intrusionSet
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default IntrusionSetEditionFragment;
