import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import EventEditionOverview from './EventEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const EventEditionContainer = (props) => {
  const { t } = useFormatter();

  const { handleClose, event, open } = props;
  const { editContext } = event;

  return (
    <Drawer
      title={t('Update an event')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
    >
      <EventEditionOverview
        event={event}
        enableReferences={useIsEnforceReference('Event')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

const EventEditionFragment = createFragmentContainer(EventEditionContainer, {
  event: graphql`
    fragment EventEditionContainer_event on Event {
      id
      ...EventEditionOverview_event
      editContext {
        name
        focusOn
      }
    }
  `,
});

export default EventEditionFragment;
