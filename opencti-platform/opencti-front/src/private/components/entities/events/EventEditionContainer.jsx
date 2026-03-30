import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import EventEditionOverview from './EventEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';

const EventEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();

  const { handleClose, event, open, controlledDial } = props;
  const { editContext } = event;

  return (
    <Drawer
      title={t_i18n('', { id: 'Update ...', values: { entity_type: translateEntityType('Event') } })}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
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
