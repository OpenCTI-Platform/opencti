import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import ThreatActorIndividualEditionOverview from './ThreatActorIndividualEditionOverview';
import ThreatActorIndividualEditionDemographics from './ThreatActorIndividualEditionDemographics';
import ThreatActorIndividualEditionBiographics from './ThreatActorIndividualEditionBiographics';
import { ThreatActorIndividualEditionContainerQuery } from './__generated__/ThreatActorIndividualEditionContainerQuery.graphql';
import ThreatActorIndividualEditionDetails from './ThreatActorIndividualEditionDetails';

interface ThreatActorIndividualEditionContainerProps {
  queryRef: PreloadedQuery<ThreatActorIndividualEditionContainerQuery>
  handleClose: () => void
  open?: boolean
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
const ThreatActorIndividualEditionContainer: FunctionComponent<ThreatActorIndividualEditionContainerProps> = ({ handleClose, queryRef, open }) => {
  const { t } = useFormatter();
  const { threatActorIndividual } = usePreloadedQuery<ThreatActorIndividualEditionContainerQuery>(ThreatActorIndividualEditionQuery, queryRef);

  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (event: React.SyntheticEvent, value: number) => setCurrentTab(value);

  if (threatActorIndividual !== null) {
    return (
      <Drawer
        title={t('Update a threat actor individual')}
        variant={open == null ? DrawerVariant.update : undefined}
        context={threatActorIndividual.editContext}
        onClose={handleClose}
        open={open}
      >
        {({ onClose }) => (
          <>
            <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Tabs value={currentTab} onChange={handleChangeTab}>
                <Tab label={t('Overview')} />
                <Tab label={t('Details')} />
              <Tab label={t('Demographics')} />
            <Tab label={t('Biographics')} />
          </Tabs>
            </Box>
            {currentTab === 0 && (
              <ThreatActorIndividualEditionOverview
                threatActorIndividualRef={threatActorIndividual}
                enableReferences={useIsEnforceReference(THREAT_ACTOR_TYPE)}
                context={threatActorIndividual.editContext}
                handleClose={onClose}
              />
            )}
            {currentTab === 1 && (
              <ThreatActorIndividualEditionDetails
                threatActorIndividualRef={threatActorIndividual}
                enableReferences={useIsEnforceReference(THREAT_ACTOR_TYPE)}
                context={threatActorIndividual.editContext}
                handleClose={onClose}
              />
            )}
            {currentTab === 2 && (
              <ThreatActorIndividualEditionDemographics
                threatActorIndividualRef={threatActorIndividual}
                enableReferences={useIsEnforceReference(THREAT_ACTOR_TYPE)}
                context={threatActorIndividual.editContext}
              />
            )}
            {currentTab === 3 && (
              <ThreatActorIndividualEditionBiographics
                threatActorIndividualRef={threatActorIndividual}
                enableReferences={useIsEnforceReference(THREAT_ACTOR_TYPE)}
                context={threatActorIndividual.editContext}
              />
            )}
          </>
        )}
      </Drawer>
    );
  }
  return <ErrorNotFound />;
};

export default ThreatActorIndividualEditionContainer;
