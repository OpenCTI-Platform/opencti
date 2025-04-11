import React from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import useAuth from '../../../../utils/hooks/useAuth';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import EntityStixCoreRelationshipsIndicators from '../../common/stix_core_relationships/views/indicators/EntityStixCoreRelationshipsIndicators';
import EntityStixCoreRelationshipsStixCyberObservable from '../../common/stix_core_relationships/views/stix_cyber_observable/EntityStixCoreRelationshipsStixCyberObservable';
import { getRelationshipTypesForEntityType } from '../../../../utils/Relation';

const threatActorGroupKnowledgeFragment = graphql`
  fragment ThreatActorGroupKnowledge_ThreatActorGroup on ThreatActorGroup {
    id
    name
    aliases
    first_seen
    last_seen
    entity_type
  }
`;

const ThreatActorGroupKnowledgeComponent = ({
  threatActorGroupData,
  relatedRelationshipTypes,
}) => {
  const threatActorGroup = useFragment(
    threatActorGroupKnowledgeFragment,
    threatActorGroupData,
  );
  const location = useLocation();
  const link = `/dashboard/threats/threat_actors_group/${threatActorGroup.id}/knowledge`;
  const { schema } = useAuth();
  const allRelationshipsTypes = getRelationshipTypesForEntityType(threatActorGroup.entity_type, schema);
  return (
    <>
      <Routes>
        <Route
          path="/relations/:relationId"
          element={
            <StixCoreRelationship
              entityId={threatActorGroup.id}
              paddingRight={true}
            />
            }
        />
        <Route
          path="/sightings/:sightingId"
          element={
            <StixSightingRelationship
              entityId={threatActorGroup.id}
              paddingRight={true}
            />
            }
        />
        <Route
          path="/overview"
          element={
            <StixDomainObjectThreatKnowledge
              stixDomainObjectId={threatActorGroup.id}
              stixDomainObjectName={threatActorGroup.name}
              stixDomainObjectType="Threat-Actor-Group"
            />
            }
        />
        <Route
          path="/all"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorGroup.id}
              relationshipTypes={allRelationshipsTypes}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              allDirections
            />
            }
        />
        <Route
          path="/related"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorGroup.id}
              relationshipTypes={relatedRelationshipTypes}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              allDirections
            />
            }
        />
        <Route
          path="/victimology"
          element={
            <StixDomainObjectVictimology
              stixDomainObjectId={threatActorGroup.id}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
            />
            }
        />
        <Route
          path="/threat_actors"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorGroup.id}
              relationshipTypes={['part-of', 'cooperates-with', 'employed-by', 'derived-from']}
              stixCoreObjectTypes={['Threat-Actor']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              allDirections
            />
            }
        />
        <Route
          path="/intrusion_sets"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorGroup.id}
              relationshipTypes={['attributed-to']}
              stixCoreObjectTypes={['Intrusion-Set']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              isRelationReversed={true}
            />
            }
        />
        <Route
          path="/campaigns"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorGroup.id}
              relationshipTypes={['attributed-to', 'participates-in']}
              stixCoreObjectTypes={['Campaign']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              allDirections
            />
            }
        />
        <Route
          path="/attack_patterns"
          element={
            <StixDomainObjectAttackPatterns
              stixDomainObjectId={threatActorGroup.id}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
            />
            }
        />
        <Route
          path="/malwares"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorGroup.id}
              relationshipTypes={['uses', 'authored-by']}
              stixCoreObjectTypes={['Malware']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              allDirections
            />
            }
        />
        <Route
          path="/channels"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorGroup.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Channel']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
            />
            }
        />
        <Route
          path="/narratives"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorGroup.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Narrative']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
            />
            }
        />
        <Route
          path="/tools"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorGroup.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Tool']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
            />
            }
        />
        <Route
          path="/vulnerabilities"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorGroup.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Vulnerability']}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
            />
            }
        />
        <Route
          path="/incidents"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorGroup.id}
              relationshipTypes={['attributed-to']}
              stixCoreObjectTypes={['Incident']}
              entityLink={link}
              isRelationReversed={true}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
            />
            }
        />
        <Route
          path="/indicators"
          element={
            <EntityStixCoreRelationshipsIndicators
              entityId={threatActorGroup.id}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
            />
            }
        />
        <Route
          path="/observables"
          element={
            <EntityStixCoreRelationshipsStixCyberObservable
              entityId={threatActorGroup.id}
              entityLink={link}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
              isRelationReversed={true}
              relationshipTypes={['related-to']}
            />
            }
        />
        <Route
          path="/infrastructures"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorGroup.id}
              relationshipTypes={['uses', 'compromises']}
              stixCoreObjectTypes={['Infrastructure']}
              entityLink={link}
              isRelationReversed={false}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
            />
            }
        />
        <Route
          path="/sightings"
          element={
            <EntityStixSightingRelationships
              entityId={threatActorGroup.id}
              entityLink={link}
              noRightBar={true}
              defaultStartTime={threatActorGroup.first_seen}
              defaultStopTime={threatActorGroup.last_seen}
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

export default ThreatActorGroupKnowledgeComponent;
