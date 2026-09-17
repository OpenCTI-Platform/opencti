import React, { FunctionComponent, useState } from 'react';
import { createFragmentContainer, graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerControlledDialType } from '@components/common/drawer/Drawer';
import { IncidentEditionOverview_incident$key } from '@components/events/incidents/__generated__/IncidentEditionOverview_incident.graphql';
import { IncidentEditionDetails_incident$key } from '@components/events/incidents/__generated__/IncidentEditionDetails_incident.graphql';
import { useFormatter } from '../../../../components/i18n';
import IncidentEditionOverview from './IncidentEditionOverview';
import IncidentEditionDetails from './IncidentEditionDetails';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { IncidentEditionContainerQuery } from './__generated__/IncidentEditionContainerQuery.graphql';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';

interface IncidentEditionContainerProps {
  queryRef: PreloadedQuery<IncidentEditionContainerQuery>;
  handleClose: () => void;
  open?: boolean;
  controlledDial?: DrawerControlledDialType;
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

const IncidentEditionContainer: FunctionComponent<IncidentEditionContainerProps> = ({
  queryRef,
  handleClose,
  open,
  controlledDial,
}) => {
  const { t_i18n } = useFormatter();
  const { incident } = usePreloadedQuery(IncidentEditionQuery, queryRef);
  const [currentTab, setCurrentTab] = useState('overview');
  const enableReferences = useIsEnforceReference('Incident');

  if (incident === null) {
    return <ErrorNotFound />;
  }
  return (
    <Drawer
      title={t_i18n('Update an incident')}
      controlledDial={controlledDial}
      context={incident?.editContext}
      onClose={handleClose}
      open={open}
    >
      {({ onClose }) => (
        <>
          <Tabs value={currentTab} onValueChange={setCurrentTab}>
            <TabsList>
              <TabsTrigger value="overview">{t_i18n('Overview')}</TabsTrigger>
              <TabsTrigger value="details">{t_i18n('Details')}</TabsTrigger>
            </TabsList>

            <TabsContent value="overview">
              <IncidentEditionOverview
                incidentRef={incident as IncidentEditionOverview_incident$key}
                enableReferences={enableReferences}
                context={incident?.editContext}
                handleClose={onClose}
              />
            </TabsContent>
            <TabsContent value="details">
              <IncidentEditionDetails
                incidentRef={incident as IncidentEditionDetails_incident$key}
                enableReferences={enableReferences}
                context={incident?.editContext}
                handleClose={onClose}
              />
            </TabsContent>
          </Tabs>
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
