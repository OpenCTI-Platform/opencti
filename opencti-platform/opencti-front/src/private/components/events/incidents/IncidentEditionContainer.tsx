import React, { FunctionComponent, useState } from 'react';
import { createFragmentContainer, graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import IncidentEditionOverview from './IncidentEditionOverview';
import IncidentEditionDetails from './IncidentEditionDetails';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { IncidentEditionContainerQuery } from './__generated__/IncidentEditionContainerQuery.graphql';

interface IncidentEditionContainerProps {
  queryRef: PreloadedQuery<IncidentEditionContainerQuery>
  handleClose: () => void
  open?: boolean
}

export const IncidentEditionQuery = graphql`
  query IncidentEditionContainerQuery($id: String!) {
    incident(id: $id) {
      ...IncidentEditionOverview_incident
      ...IncidentEditionDetails_incident
      ...IncidentDetails_incident
      editContext {
        name
        focusOn
      }
    }
  }
`;

const IncidentEditionContainer: FunctionComponent<IncidentEditionContainerProps> = ({ queryRef, handleClose, open }) => {
  const { t } = useFormatter();

  const { incident } = usePreloadedQuery(IncidentEditionQuery, queryRef);
  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (event: React.SyntheticEvent, value: number) => setCurrentTab(value);

  if (incident === null) {
    return <ErrorNotFound />;
  }
  return (
    <Drawer
      title={t('Update an incident')}
      variant={open == null ? DrawerVariant.update : undefined}
      context={incident.editContext}
      onClose={handleClose}
      open={open}
    >
      {({ onClose }) => (
        <>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs value={currentTab} onChange={handleChangeTab}>
              <Tab label={t('Overview')} />
              <Tab label={t('Details')} />
            </Tabs>
          </Box>
          {currentTab === 0 && (
            <IncidentEditionOverview
              incidentRef={incident}
              enableReferences={useIsEnforceReference('Incident')}
              context={incident.editContext}
              handleClose={onClose}
            />
          )}
          {currentTab === 1 && (
            <IncidentEditionDetails
              incidentRef={incident}
              enableReferences={useIsEnforceReference('Incident')}
              context={incident.editContext}
              handleClose={onClose}
            />
          )}
        </>
      )}
    </Drawer>
  );
};

const IncidentEditionContainerFragment = createFragmentContainer(
  IncidentEditionContainer,
  {
    incident: graphql`
      fragment IncidentEditionContainer_incident on Incident {
        id
        ...IncidentEditionOverview_incident
        ...IncidentEditionDetails_incident
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default IncidentEditionContainerFragment;
