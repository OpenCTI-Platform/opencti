import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Drawer from '@components/common/drawer/Drawer';
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
import ThreatActorIndividualDelete from './ThreatActorIndividualDelete';

interface ThreatActorIndividualEditionContainerProps {
  queryRef: PreloadedQuery<ThreatActorIndividualEditionContainerQuery>;
  handleClose: () => void;
  open?: boolean;
  controlledDial?: ({ onOpen, onClose }:{ onOpen: () => void, onClose: () => void }) => React.ReactElement;
}

export const ThreatActorIndividualEditionQuery = graphql`
  query ThreatActorIndividualEditionContainerQuery($id: String!) {
    threatActorIndividual(id: $id) {
      ...ThreatActorIndividualEditionOverview_ThreatActorIndividual
      ...ThreatActorIndividualEditionDetails_ThreatActorIndividual
      ...ThreatActorIndividualEditionBiographics_ThreatActorIndividual
      ...ThreatActorIndividualEditionDemographics_ThreatActorIndividual
      ...ThreatActorIndividualDetails_ThreatActorIndividual
      id
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

  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (event: React.SyntheticEvent, value: number) => setCurrentTab(value);

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
            <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Tabs value={currentTab} onChange={handleChangeTab}>
                <Tab label={t_i18n('Overview')} />
                <Tab label={t_i18n('Details')} />
                <Tab label={t_i18n('Demographics')} />
                <Tab label={t_i18n('Biographics')} />
              </Tabs>
            </Box>
            {currentTab === 0 && (
              <ThreatActorIndividualEditionOverview
                threatActorIndividualRef={threatActorIndividual as ThreatActorIndividualEditionOverview_ThreatActorIndividual$key}
                enableReferences={useIsEnforceReference(THREAT_ACTOR_TYPE)}
                context={threatActorIndividual?.editContext}
                handleClose={onClose}
              />
            )}
            {currentTab === 1 && (
              <ThreatActorIndividualEditionDetails
                threatActorIndividualRef={threatActorIndividual as ThreatActorIndividualEditionDetails_ThreatActorIndividual$key}
                enableReferences={useIsEnforceReference(THREAT_ACTOR_TYPE)}
                context={threatActorIndividual?.editContext}
                handleClose={onClose}
              />
            )}
            {currentTab === 2 && (
              <ThreatActorIndividualEditionDemographics
                threatActorIndividualRef={threatActorIndividual as ThreatActorIndividualEditionDemographics_ThreatActorIndividual$key}
                enableReferences={useIsEnforceReference(THREAT_ACTOR_TYPE)}
                context={threatActorIndividual?.editContext}
              />
            )}
            {currentTab === 3 && (
              <ThreatActorIndividualEditionBiographics
                threatActorIndividualRef={threatActorIndividual as ThreatActorIndividualEditionBiographics_ThreatActorIndividual$key}
                enableReferences={useIsEnforceReference(THREAT_ACTOR_TYPE)}
                context={threatActorIndividual?.editContext}
              />
            )}
            {!useIsEnforceReference(THREAT_ACTOR_TYPE) && threatActorIndividual?.id
              && <ThreatActorIndividualDelete id={threatActorIndividual.id} />
            }
          </>
        )}
      </Drawer>
    );
  }
  return <ErrorNotFound />;
};

export default ThreatActorIndividualEditionContainer;
