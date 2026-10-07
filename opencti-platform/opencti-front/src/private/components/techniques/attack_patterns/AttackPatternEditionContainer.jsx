import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';
import AttackPatternEditionOverview from './AttackPatternEditionOverview';
import AttackPatternEditionDetails from './AttackPatternEditionDetails';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { useFormatter } from '../../../../components/i18n';
import Drawer from '../../common/drawer/Drawer';

const AttackPatternEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const { handleClose, attackPattern, open, controlledDial } = props;
  const { editContext } = attackPattern;

  const [currentTab, setCurrentTab] = useState('overview');
  const enableReferences = useIsEnforceReference('Attack-Pattern');

  return (
    <Drawer
      title={t_i18n('Update an attack pattern')}
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
          <AttackPatternEditionOverview
            attackPattern={attackPattern}
            enableReferences={enableReferences}
            context={editContext}
            handleClose={handleClose}
          />
        </TabsContent>
        <TabsContent value="details">
          <AttackPatternEditionDetails
            attackPattern={attackPattern}
            enableReferences={enableReferences}
            context={editContext}
            handleClose={handleClose}
          />
        </TabsContent>
      </Tabs>
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
