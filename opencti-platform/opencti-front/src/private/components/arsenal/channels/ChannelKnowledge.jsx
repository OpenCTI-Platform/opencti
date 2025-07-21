import React from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import { getRelationshipTypesForEntityType } from '../../../../utils/Relation';
import useAuth from '../../../../utils/hooks/useAuth';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';
import EntityStixCoreRelationshipsStixCyberObservable from '../../common/stix_core_relationships/views/stix_cyber_observable/EntityStixCoreRelationshipsStixCyberObservable';

const channelKnowledgeFragment = graphql`
  fragment ChannelKnowledge_channel on Channel {
    id
    name
    aliases
    entity_type
  }
`;

const ChannelKnowledgeComponent = ({
  channelData,
}) => {
  const channel = useFragment(
    channelKnowledgeFragment,
    channelData,
  );
  const location = useLocation();
  const link = `/dashboard/arsenal/channels/${channel.id}/knowledge`;
  const { schema } = useAuth();
  const allRelationshipsTypes = getRelationshipTypesForEntityType(channel.entity_type, schema);
  return (
    <div data-testid="channel-knowledge">
      <Routes>
        <Route
          path="/relations/:relationId"
          element={
            <StixCoreRelationship
              entityId={channel.id}
              paddingRight={true}
            />
            }
        />
        <Route
          path="/sightings/:sightingId"
          element={
            <StixSightingRelationship
              entityId={channel.id}
              paddingRight={true}
            />
            }
        />
        <Route
          path="/overview"
          element={
            <StixDomainObjectThreatKnowledge
              stixDomainObjectId={channel.id}
              stixDomainObjectName={channel.name}
              stixDomainObjectType="Channel"
            />
            }
        />
        <Route
          path="/all"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={channel.id}
              relationshipTypes={allRelationshipsTypes}
              entityLink={link}
              defaultStartTime={channel.startTime}
              defaultStopTime={channel.stopTime}
              allDirections
            />
            }
        />
        <Route
          path="/related"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={channel.id}
              relationshipTypes={['related-to']}
              entityLink={link}
              allDirections={true}
            />
            }
        />
        <Route
          path="/victimology"
          element={
            <StixDomainObjectVictimology
              stixDomainObjectId={channel.id}
              entityLink={link}
            />
            }
        />
        <Route
          path="/threats"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              allDirections
              entityId={channel.id}
              relationshipTypes={['uses', 'belongs-to']}
              isRelationReversed={true}
              entityLink={link}
              stixCoreObjectTypes={[
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
          path="/threat_actors"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={channel.id}
              relationshipTypes={['uses', 'belongs-to']}
              stixCoreObjectTypes={['Threat-Actor']}
              entityLink={link}
              isRelationReversed={true}
              allDirections
            />
          }
        />
        <Route
          path="/intrusion_sets"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={channel.id}
              relationshipTypes={['uses', 'belongs-to']}
              stixCoreObjectTypes={['Intrusion-Set']}
              entityLink={link}
              isRelationReversed={true}
              allDirections
            />
          }
        />
        <Route
          path="/campaigns"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={channel.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Campaign']}
              entityLink={link}
              isRelationReversed={true}
            />
            }
        />
        <Route
          path="/attack_patterns"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={channel.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Attack-Pattern']}
              entityLink={link}
              isRelationReversed={false}
            />
            }
        />
        <Route
          path="/channels"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={channel.id}
              relationshipTypes={['amplifies', 'derived-from', 'belongs-to']}
              stixCoreObjectTypes={['Channel']}
              entityLink={link}
              isRelationReversed={false}
              allDirections
            />
            }
        />
        <Route
          path="/malwares"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={channel.id}
              relationshipTypes={['uses', 'delivers', 'drops']}
              stixCoreObjectTypes={['Malware']}
              entityLink={link}
              isRelationReversed={false}
            />
            }
        />
        <Route
          path="/vulnerabilities"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={channel.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Vulnerability']}
              entityLink={link}
              isRelationReversed={false}
            />
            }
        />
        <Route
          path="/incidents"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={channel.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Incident']}
              entityLink={link}
              isRelationReversed={true}
            />
            }
        />
        <Route
          path="/observables"
          element={
            <EntityStixCoreRelationshipsStixCyberObservable
              entityId={channel.id}
              entityLink={link}
              defaultStartTime={channel.first_seen}
              defaultStopTime={channel.last_seen}
              isRelationReversed={true}
              relationshipTypes={[
                'related-to',
                'publishes',
                'uses',
                'belongs-to',
              ]}
            />
            }
        />
        <Route
          path="/sightings"
          element={
            <EntityStixSightingRelationships
              entityId={channel.id}
              entityLink={link}
              noRightBar={true}
              stixCoreObjectTypes={[
                'Region',
                'Country',
                'City',
                'Position',
                'Sector',
                'Organization',
                'Individual',
                'System',
              ]}
            />
            }
        />
      </Routes>
    </div>
  );
};

export default ChannelKnowledgeComponent;
