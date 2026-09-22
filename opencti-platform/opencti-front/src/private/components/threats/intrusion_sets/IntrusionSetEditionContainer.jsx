import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import IntrusionSetEditionOverview from './IntrusionSetEditionOverview';
import IntrusionSetEditionDetails from './IntrusionSetEditionDetails';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';

const IntrusionSetEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const { handleClose, intrusionSet, open, controlledDial } = props;
  const { editContext } = intrusionSet;

  const [currentTab, setCurrentTab] = useState('overview');
  const enableReferences = useIsEnforceReference('Intrusion-Set');

  return (
    <Drawer
      title={t_i18n('Update an intrusion set')}
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
          <IntrusionSetEditionOverview
            intrusionSet={intrusionSet}
            enableReferences={enableReferences}
            context={editContext}
            handleClose={handleClose}
          />
        </TabsContent>
        <TabsContent value="details">
          <IntrusionSetEditionDetails
            intrusionSet={intrusionSet}
            enableReferences={enableReferences}
            context={editContext}
            handleClose={handleClose}
          />
        </TabsContent>
      </Tabs>
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
