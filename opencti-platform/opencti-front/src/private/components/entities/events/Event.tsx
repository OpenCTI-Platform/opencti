import { useInitCreateRelationshipContext } from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import { Grid } from '@mui/material';
import React from 'react';
import { useFragment } from 'react-relay';
import { graphql } from 'relay-runtime';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import { Event_event$key } from './__generated__/Event_event.graphql';
import EventDetails from './EventDetails';

const eventFragment = graphql`
  fragment Event_event on Event {
    id
    standard_id
    entity_type
    x_opencti_stix_ids
    spec_version
    revoked
    confidence
    created
    modified
    created_at
    updated_at
    createdBy {
      ... on Identity {
        id
        name
        entity_type
        x_opencti_reliability
      }
    }
    creators {
      id
      name
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    name
    aliases
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    ...WorkflowStatusStixDomainObject_data
    ...EventDetails_event
  }
`;

interface EventProps {
  eventData: Event_event$key;
}

const Event: React.FC<EventProps> = ({
  eventData,
}) => {
  useInitCreateRelationshipContext();

  const event = useFragment<Event_event$key>(
    eventFragment,
    eventData,
  );
  return (
    <div data-testid="event-details-page">
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        <Grid item xs={6}>
          <EventDetails event={event} />
        </Grid>
        <Grid item xs={6}>
          <StixDomainObjectOverview
            stixDomainObject={event}
          />
        </Grid>
        <Grid item xs={6}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={event.id}
            stixObjectOrStixRelationshipLink={`/dashboard/entities/events/${event.id}/knowledge`}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={event.id}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectExternalReferences stixCoreObjectId={event.id} />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={event.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={event.id}
        defaultMarkings={event.objectMarking ?? []}
      />
    </div>
  );
};

export default Event;
