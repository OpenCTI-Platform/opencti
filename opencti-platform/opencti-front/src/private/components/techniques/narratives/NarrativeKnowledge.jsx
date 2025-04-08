import React from 'react';
import { Route, Routes } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import useAuth from '../../../../utils/hooks/useAuth';
import { getRelationshipTypesForEntityType } from '../../../../utils/Relation';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import EntityStixCoreRelationshipsStixCyberObservable from '../../common/stix_core_relationships/views/stix_cyber_observable/EntityStixCoreRelationshipsStixCyberObservable';

const NarrativeKnowledgeFragment = graphql`
  fragment NarrativeKnowledge_narrative on Narrative {
    id
    name
    aliases
    entity_type
  }
`;

const NarrativeKnowledgeComponent = ({
  narrativeData,
}) => {
  const narrative = useFragment(
    NarrativeKnowledgeFragment,
    narrativeData,
  );
  const link = `/dashboard/techniques/narratives/${narrative.id}/knowledge`;
  const { schema } = useAuth();
  const allRelationshipsTypes = getRelationshipTypesForEntityType(narrative.entity_type, schema);
  return (
    <>
      <Routes>
        <Route
          path="/relations/:relationId"
          element={
            <StixCoreRelationship
              entityId={narrative.id}
              paddingRight={true}
            />
            }
        />
        <Route
          path="/sightings/:sightingId"
          element={
            <StixSightingRelationship
              entityId={narrative.id}
              paddingRight={true}
            />
            }
        />
        <Route
          path="/overview"
          element={
            <StixDomainObjectKnowledge
              stixDomainObjectId={narrative.id}
              stixDomainObjectType="Narrative"
            />
            }
        />
        <Route
          path="/all"
          element={
            <EntityStixCoreRelationships
              entityId={narrative.id}
              relationshipTypes={allRelationshipsTypes}
              defaultStartTime={narrative.startTime}
              defaultStopTime={narrative.stopTime}
              entityLink={link}
              allDirections
            />
            }
        />
        <Route
          path="/related"
          element={
            <EntityStixCoreRelationships
              entityId={narrative.id}
              relationshipTypes={['related-to']}
              stixCoreObjectTypes={[
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'Incident',
                'Malware',
                'Narrative',
                'Vulnerability',
                'Individual',
                'Organization',
                'Sector',
                'Region',
                'Country',
                'City',
                'Position',
              ]}
              entityLink={link}
              allDirections={true}
            />
            }
        />
        <Route
          path="/threat_actors"
          element={
            <EntityStixCoreRelationships
              entityId={narrative.id}
              relationshipTypes={['uses']}
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
              entityId={narrative.id}
              relationshipTypes={['uses']}
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
              entityId={narrative.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Campaign']}
              entityLink={link}
              isRelationReversed={true}
            />
            }
        />
        <Route
          path="/channels"
          element={
            <EntityStixCoreRelationships
              entityId={narrative.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Channel']}
              entityLink={link}
              isRelationReversed={true}
            />
            }
        />
        <Route
          path="/incidents"
          element={
            <EntityStixCoreRelationships
              entityId={narrative.id}
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
              entityId={narrative.id}
              entityLink={link}
              defaultStartTime={narrative.first_seen}
              defaultStopTime={narrative.last_seen}
              isRelationReversed={true}
              relationshipTypes={['related-to']}
            />
            }
        />
        <Route
          path="/sightings"
          element={
            <EntityStixSightingRelationships
              entityId={narrative.id}
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
    </>
  );
};

export default NarrativeKnowledgeComponent;
