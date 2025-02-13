import React from 'react';
import { Route, Routes } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import { getRelationshipTypesForEntityType } from '../../../../utils/Relation';
import useAuth from '../../../../utils/hooks/useAuth';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const eventKnowledgeFragment = graphql`
  fragment EventKnowledge_event on Event {
    id
    name
    aliases
    entity_type
  }
`;

const EventKnowledgeComponent = ({
  eventData,
}) => {
  const event = useFragment(
    eventKnowledgeFragment,
    eventData,
  );
  const link = `/dashboard/entities/events/${event.id}/knowledge`;
  const { schema } = useAuth();
  const allRelationshipsTypes = getRelationshipTypesForEntityType(event.entity_type, schema);

  return (
    <>
      <Routes>
        <Route
          path="/relations/:relationId"
          element={
            <StixCoreRelationship
              entityId={event.id}
              paddingRight={true}
            />
            }
        />
        <Route
          path="/sightings/:sightingId"
          element={
            <StixSightingRelationship
              entityId={event.id}
              paddingRight={true}
            />
            }
        />
        <Route
          path="/overview"
          element={
            <StixDomainObjectKnowledge
              stixDomainObjectId={event.id}
              stixDomainObjectType="Event"
            />
            }
        />
        <Route
          path="/all"
          element={
            <EntityStixCoreRelationships
              entityId={event.id}
              relationshipTypes={allRelationshipsTypes}
              entityLink={link}
              defaultStartTime={event.startTime}
              defaultStopTime={event.stopTime}
              allDirections
            />
            }
        />
        <Route
          path="/threats"
          element={
            <EntityStixCoreRelationships
              entityId={event.id}
              relationshipTypes={['targets']}
              isRelationReversed
              entityLink={link}
              stixCoreObjectTypes={[
                'Attack-Pattern',
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'Incident',
                'Malware',
                'Tool',
              ]}
            />
            }
        />
        <Route
          path="/related"
          element={
            <EntityStixCoreRelationships
              entityId={event.id}
              relationshipTypes={['related-to']}
              entityLink={link}
              allDirections={true}
            />
            }
        />
        <Route
          path="/locations"
          element={
            <EntityStixCoreRelationships
              entityId={event.id}
              relationshipTypes={['located-at']}
              stixCoreObjectTypes={['City', 'Country', 'Region']}
              entityLink={link}
              isRelationReversed={false}
            />
            }
        />
        <Route
          path="/threat_actors"
          element={
            <EntityStixCoreRelationships
              entityId={event.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Threat-Actor']}
              entityLink={link}
              isRelationReversed={true}
            />
            }
        />
        <Route
          path="/intrusion_sets"
          element={
            <EntityStixCoreRelationships
              entityId={event.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Intrusion-Set']}
              entityLink={link}
              isRelationReversed={true}
            />
            }
        />
        <Route
          path="/campaigns"
          element={
            <EntityStixCoreRelationships
              entityId={event.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Campaign']}
              entityLink={link}
              isRelationReversed={true}
            />
            }
        />
        <Route
          path="/incidents"
          element={
            <EntityStixCoreRelationships
              entityId={event.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Incident']}
              entityLink={link}
              isRelationReversed={true}
            />
            }
        />
        <Route
          path="/malwares"
          element={
            <EntityStixCoreRelationships
              entityId={event.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Malware']}
              entityLink={link}
              isRelationReversed={true}
            />
            }
        />
        <Route
          path="/attack_patterns"
          element={
            <EntityStixCoreRelationships
              entityId={event.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Attack-Pattern']}
              entityLink={link}
              isRelationReversed={true}
            />
            }
        />
        <Route
          path="/tools"
          element={
            <EntityStixCoreRelationships
              entityId={event.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Tool']}
              entityLink={link}
              isRelationReversed={true}
            />
            }
        />
        <Route
          path="/observables"
          element={
            <EntityStixCoreRelationships
              entityId={event.id}
              relationshipTypes={['related-to']}
              stixCoreObjectTypes={['Stix-Cyber-Observable']}
              entityLink={link}
              allDirections={true}
              isRelationReversed={true}
            />
            }
        />
      </Routes>
    </>
  );
};

export default EventKnowledgeComponent;
