import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerControlledDialType } from '@components/common/drawer/Drawer';
import {
  ThreatActorIndividualEditionOverview_ThreatActorIndividual$key,
} from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividualEditionOverview_ThreatActorIndividual.graphql';
import {
  ThreatActorIndividualEditionDetails_ThreatActorIndividual$key,
} from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividualEditionDetails_ThreatActorIndividual.graphql';
import {
  ThreatActorIndividualEditionDemographics_ThreatActorIndividual$key,
} from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividualEditionDemographics_ThreatActorIndividual.graphql';
import {
  ThreatActorIndividualEditionBiographics_ThreatActorIndividual$key,
} from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividualEditionBiographics_ThreatActorIndividual.graphql';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import ThreatActorIndividualEditionOverview from './ThreatActorIndividualEditionOverview';
import ThreatActorIndividualEditionDemographics from './ThreatActorIndividualEditionDemographics';
import ThreatActorIndividualEditionBiographics from './ThreatActorIndividualEditionBiographics';
import { ThreatActorIndividualEditionContainerQuery } from './__generated__/ThreatActorIndividualEditionContainerQuery.graphql';
import ThreatActorIndividualEditionDetails from './ThreatActorIndividualEditionDetails';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';

interface ThreatActorIndividualEditionContainerProps {
  queryRef: PreloadedQuery<ThreatActorIndividualEditionContainerQuery>;
  handleClose: () => void;
  open?: boolean;
  controlledDial?: DrawerControlledDialType;
}

export const ThreatActorIndividualEditionQuery = graphql`
  query ThreatActorIndividualEditionContainerQuery($id: String!) {
    threatActorIndividual(id: $id) {
      ...ThreatActorIndividualEditionOverview_ThreatActorIndividual
      ...ThreatActorIndividualEditionDetails_ThreatActorIndividual
      ...ThreatActorIndividualEditionBiographics_ThreatActorIndividual
      ...ThreatActorIndividualEditionDemographics_ThreatActorIndividual
      ...ThreatActorIndividualDetails_ThreatActorIndividual
      editContext {
        name
        focusOn
      }
    }
  }
`;

const THREAT_ACTOR_TYPE = 'Threat-Actor-Individual';
const ThreatActorIndividualEditionContainer: FunctionComponent<
  ThreatActorIndividualEditionContainerProps
> = ({ handleClose, queryRef, open, controlledDial }) => {
  const { t_i18n } = useFormatter();
  const { threatActorIndividual } = usePreloadedQuery<ThreatActorIndividualEditionContainerQuery>(
    ThreatActorIndividualEditionQuery,
    queryRef,
  );

  const [currentTab, setCurrentTab] = useState('overview');
  const enableReferences = useIsEnforceReference(THREAT_ACTOR_TYPE);

  if (threatActorIndividual !== null) {
    return (
      <Drawer
        title={t_i18n('Update a threat actor individual')}
        context={threatActorIndividual?.editContext}
        onClose={handleClose}
        open={open}
        controlledDial={controlledDial}
      >
        {({ onClose }) => (
          <>
            <Tabs value={currentTab} onValueChange={setCurrentTab}>
              <TabsList>
                <TabsTrigger value="overview">{t_i18n('Overview')}</TabsTrigger>
                <TabsTrigger value="details">{t_i18n('Details')}</TabsTrigger>
                <TabsTrigger value="demographics">{t_i18n('Demographics')}</TabsTrigger>
                <TabsTrigger value="biographics">{t_i18n('Biographics')}</TabsTrigger>
              </TabsList>

              <TabsContent value="overview">
                <ThreatActorIndividualEditionOverview
                  threatActorIndividualRef={threatActorIndividual as ThreatActorIndividualEditionOverview_ThreatActorIndividual$key}
                  enableReferences={enableReferences}
                  context={threatActorIndividual?.editContext}
                  handleClose={onClose}
                />
              </TabsContent>
              <TabsContent value="details">
                <ThreatActorIndividualEditionDetails
                  threatActorIndividualRef={threatActorIndividual as ThreatActorIndividualEditionDetails_ThreatActorIndividual$key}
                  enableReferences={enableReferences}
                  context={threatActorIndividual?.editContext}
                  handleClose={onClose}
                />
              </TabsContent>
              <TabsContent value="demographics">
                <ThreatActorIndividualEditionDemographics
                  threatActorIndividualRef={threatActorIndividual as ThreatActorIndividualEditionDemographics_ThreatActorIndividual$key}
                  enableReferences={enableReferences}
                  context={threatActorIndividual?.editContext}
                />
              </TabsContent>
              <TabsContent value="biographics">
                <ThreatActorIndividualEditionBiographics
                  threatActorIndividualRef={threatActorIndividual as ThreatActorIndividualEditionBiographics_ThreatActorIndividual$key}
                  enableReferences={enableReferences}
                  context={threatActorIndividual?.editContext}
                />
              </TabsContent>
            </Tabs>
          </>
        )}
      </Drawer>
    );
  }
  return <ErrorNotFound />;
};

export default ThreatActorIndividualEditionContainer;
