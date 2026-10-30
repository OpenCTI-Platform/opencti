import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import ThreatActorGroupEditionOverview from './ThreatActorGroupEditionOverview';
import ThreatActorGroupEditionDetails from './ThreatActorGroupEditionDetails';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';

const ThreatActorGroupEditionContainer = ({
  handleClose,
  threatActorGroup,
  open,
  controlledDial,
}) => {
  const { t_i18n } = useFormatter();
  const { editContext } = threatActorGroup;
  const [currentTab, setCurrentTab] = useState('overview');
  const enableReferences = useIsEnforceReference('Threat-Actor-Group');
  return (
    <Drawer
      title={t_i18n('Update a threat actor group')}
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
          <ThreatActorGroupEditionOverview
            threatActorGroup={threatActorGroup}
            enableReferences={enableReferences}
            context={editContext}
            handleClose={handleClose}
          />
        </TabsContent>
        <TabsContent value="details">
          <ThreatActorGroupEditionDetails
            threatActorGroup={threatActorGroup}
            enableReferences={enableReferences}
            context={editContext}
            handleClose={handleClose}
          />
        </TabsContent>
      </Tabs>
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
