import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import EventEditionContainer from './EventEditionContainer';
import { eventEditionOverviewFocus } from './EventEditionOverview';
import Loader from '../../../../components/Loader';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

export const eventEditionQuery = graphql`
  query EventEditionContainerQuery($id: String!) {
    event(id: $id) {
      ...EventEditionContainer_event
    }
  }
`;

const EventEdition = (props) => {
  const handleClose = () => {
    commitMutation({
      mutation: eventEditionOverviewFocus,
      variables: {
        id: props.eventId,
        input: { focusOn: '' },
      },
    });
  };

  const { eventId } = props;
  return (
    <QueryRenderer
      query={eventEditionQuery}
      variables={{ id: eventId }}
      render={({ props }) => {
        if (props) {
          return (
            <EventEditionContainer
              event={props.event}
              handleClose={handleClose}
              controlledDial={EditEntityControlledDial}
            />
          );
        }
        return <Loader variant="inline" />;
      }}
    />
  );
};

EventEdition.propTypes = {
  eventId: PropTypes.string,
  theme: PropTypes.object,
};

export default EventEdition;
