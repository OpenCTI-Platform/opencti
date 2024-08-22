/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Routes } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import { ThreatActorIndividualKnowledge_ThreatActorIndividual$key } from './__generated__/ThreatActorIndividualKnowledge_ThreatActorIndividual.graphql';
import EntityStixCoreRelationshipsStixCyberObservable from '../../common/stix_core_relationships/views/stix_cyber_observable/EntityStixCoreRelationshipsStixCyberObservable';
import EntityStixCoreRelationshipsIndicators from '../../common/stix_core_relationships/views/indicators/EntityStixCoreRelationshipsIndicators';

const threatActorIndividualKnowledgeFragment = graphql`
  fragment ThreatActorIndividualKnowledge_ThreatActorIndividual on ThreatActorIndividual {
    id
    name
    aliases
    first_seen
    last_seen
  }
`;

const ThreatActorIndividualKnowledgeComponent = ({
  threatActorIndividualData,
}: {
  threatActorIndividualData: ThreatActorIndividualKnowledge_ThreatActorIndividual$key;
}) => {
  const threatActorIndividual = useFragment<ThreatActorIndividualKnowledge_ThreatActorIndividual$key>(
    threatActorIndividualKnowledgeFragment,
    threatActorIndividualData,
  );
  const link = `/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/knowledge`;
  return (
    <Routes>
      <Route
        path="/relations/:relationId"
        element={
          <StixCoreRelationship
            entityId={threatActorIndividual.id}
            paddingRight={true}
          />
        }
      />
      <Route
        path="/sightings/:sightingId"
        element={
          <StixSightingRelationship
            entityId={threatActorIndividual.id}
            paddingRight={true}
          />
        }
      />
      <Route
        path="/overview"
        element={
          <StixDomainObjectThreatKnowledge
            stixDomainObjectId={threatActorIndividual.id}
            stixDomainObjectName={threatActorIndividual.name}
            stixDomainObjectType="Threat-Actor-Individual"
          />
        }
      />
      <Route
        path="/related"
        element={
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['related-to', 'part-of', 'known-as', 'impersonates']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            allDirections={true}
          />
        }
      />
      <Route
        path="/victimology"
        element={
          <StixDomainObjectVictimology
            stixDomainObjectId={threatActorIndividual.id}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
          />
        }
      />
      <Route
        path="/threat_actors"
        element={
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['part-of', 'cooperates-with', 'employed-by']}
            stixCoreObjectTypes={['Threat-Actor']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            allDirections={true}
          />
        }
      />
      <Route
        path="/intrusion_sets"
        element={
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['attributed-to']}
            stixCoreObjectTypes={['Intrusion-Set']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            isRelationReversed={true}
          />
        }
      />
      <Route
        path="/campaigns"
        element={
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['attributed-to', 'participates-in']}
            stixCoreObjectTypes={['Campaign']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            allDirections={true}
          />
        }
      />
      <Route
        path="/attack_patterns"
        element={
          <StixDomainObjectAttackPatterns
            stixDomainObjectId={threatActorIndividual.id}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
          />
        }
      />
      <Route
        path="/malwares"
        element={
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['uses']}
            stixCoreObjectTypes={['Malware']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
          />
        }
      />
      <Route
        path="/channels"
        element={
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['uses']}
            stixCoreObjectTypes={['Channel']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
          />
        }
      />
      <Route
        path="/narratives"
        element={
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['uses']}
            stixCoreObjectTypes={['Narrative']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
          />
        }
      />
      <Route
        path="/tools"
        element={
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['uses']}
            stixCoreObjectTypes={['Tool']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
          />
        }
      />
      <Route
        path="/vulnerabilities"
        element={
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['targets']}
            stixCoreObjectTypes={['Vulnerability']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
          />
        }
      />
      <Route
        path="/countries"
        element={
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['resides-in', 'citizen-of', 'national-of']}
            stixCoreObjectTypes={['Country']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
          />
        }
      />
      <Route
        path="/organizations"
        element={
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['employed-by', 'impersonates']}
            stixCoreObjectTypes={['Organization']}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
          />
        }
      />
      <Route
        path="/incidents"
        element={
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['attributed-to']}
            stixCoreObjectTypes={['Incident']}
            entityLink={link}
            isRelationReversed={true}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
          />
        }
      />
      <Route
        path="/indicators"
        element={
          <EntityStixCoreRelationshipsIndicators
            entityId={threatActorIndividual.id}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
          />
        }
      />
      <Route
        path="/observables"
        element={
          <EntityStixCoreRelationshipsStixCyberObservable
            entityId={threatActorIndividual.id}
            entityLink={link}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
            isRelationReversed={false}
            relationshipTypes={['related-to', 'known-as']}
          />
        }
      />
      <Route
        path="/infrastructures"
        element={
          <EntityStixCoreRelationships
            entityId={threatActorIndividual.id}
            relationshipTypes={['uses', 'compromises']}
            stixCoreObjectTypes={['Infrastructure']}
            entityLink={link}
            isRelationReversed={false}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
          />
        }
      />
      <Route
        path="/sightings"
        element={
          <EntityStixSightingRelationships
            entityId={threatActorIndividual.id}
            entityLink={link}
            noRightBar={true}
            defaultStartTime={threatActorIndividual.first_seen}
            defaultStopTime={threatActorIndividual.last_seen}
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
  );
};

export default ThreatActorIndividualKnowledgeComponent;
