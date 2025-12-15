// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';
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
import { getRelationshipTypesForEntityType } from '../../../../utils/Relation';
import useAuth from '../../../../utils/hooks/useAuth';

const threatActorIndividualKnowledgeFragment = graphql`
  fragment ThreatActorIndividualKnowledge_ThreatActorIndividual on ThreatActorIndividual {
    id
    name
    aliases
    first_seen
    last_seen
    entity_type
  }
`;

const ThreatActorIndividualKnowledgeComponent = ({
  threatActorIndividualData,
  relatedRelationshipTypes,
}: {
  threatActorIndividualData: ThreatActorIndividualKnowledge_ThreatActorIndividual$key;
  relatedRelationshipTypes: string[];
}) => {
  const threatActorIndividual = useFragment<ThreatActorIndividualKnowledge_ThreatActorIndividual$key>(
    threatActorIndividualKnowledgeFragment,
    threatActorIndividualData,
  );
  const location = useLocation();
  const link = `/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/knowledge`;
  const { schema } = useAuth();
  const allRelationshipsTypes = getRelationshipTypesForEntityType(threatActorIndividual.entity_type, schema);
  return (
    <div data-testid="threat-actor-individual-knowledge">
      <Routes>
        <Route
          path="/relations/:relationId"
          element={(
            <StixCoreRelationship
              entityId={threatActorIndividual.id}
              paddingRight={true}
            />
          )}
        />
        <Route
          path="/sightings/:sightingId"
          element={(
            <StixSightingRelationship
              entityId={threatActorIndividual.id}
              paddingRight={true}
            />
          )}
        />
        <Route
          path="/overview"
          element={(
            <StixDomainObjectThreatKnowledge
              stixDomainObjectId={threatActorIndividual.id}
              stixDomainObjectName={threatActorIndividual.name}
              stixDomainObjectType="Threat-Actor-Individual"
            />
          )}
        />
        <Route
          path="/all"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorIndividual.id}
              relationshipTypes={allRelationshipsTypes}
              entityLink={link}
              defaultStartTime={threatActorIndividual.startTime}
              defaultStopTime={threatActorIndividual.stopTime}
              allDirections
            />
          )}
        />
        <Route
          path="/related"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorIndividual.id}
              relationshipTypes={relatedRelationshipTypes}
              entityLink={link}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
              allDirections
            />
          )}
        />
        <Route
          path="/victimology"
          element={(
            <StixDomainObjectVictimology
              stixDomainObjectId={threatActorIndividual.id}
              entityLink={link}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
            />
          )}
        />
        <Route
          path="/threat_actors"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorIndividual.id}
              relationshipTypes={[
                'part-of',
                'cooperates-with',
                'employed-by',
                'reports-to',
                'supports',
                'derived-from',
              ]}
              stixCoreObjectTypes={['Threat-Actor']}
              entityLink={link}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
              allDirections
            />
          )}
        />
        <Route
          path="/intrusion_sets"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorIndividual.id}
              relationshipTypes={['attributed-to']}
              stixCoreObjectTypes={['Intrusion-Set']}
              entityLink={link}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
              isRelationReversed={true}
            />
          )}
        />
        <Route
          path="/campaigns"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorIndividual.id}
              relationshipTypes={['attributed-to', 'participates-in']}
              stixCoreObjectTypes={['Campaign']}
              entityLink={link}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
              allDirections
            />
          )}
        />
        <Route
          path="/attack_patterns"
          element={(
            <StixDomainObjectAttackPatterns
              stixDomainObjectId={threatActorIndividual.id}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
              entityType={threatActorIndividual.entity_type}
            />
          )}
        />
        <Route
          path="/malwares"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorIndividual.id}
              relationshipTypes={['uses', 'authored-by']}
              stixCoreObjectTypes={['Malware']}
              entityLink={link}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
              allDirections
            />
          )}
        />
        <Route
          path="/channels"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorIndividual.id}
              relationshipTypes={['uses', 'belongs-to']}
              stixCoreObjectTypes={['Channel']}
              entityLink={link}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
              allDirections
            />
          )}
        />
        <Route
          path="/narratives"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorIndividual.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Narrative']}
              entityLink={link}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
            />
          )}
        />
        <Route
          path="/tools"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorIndividual.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Tool']}
              entityLink={link}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
            />
          )}
        />
        <Route
          path="/vulnerabilities"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorIndividual.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Vulnerability']}
              entityLink={link}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
            />
          )}
        />
        <Route
          path="/countries"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorIndividual.id}
              relationshipTypes={['resides-in', 'citizen-of', 'national-of']}
              stixCoreObjectTypes={['Country']}
              entityLink={link}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
            />
          )}
        />
        <Route
          path="/organizations"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorIndividual.id}
              relationshipTypes={['employed-by', 'impersonates']}
              stixCoreObjectTypes={['Organization']}
              entityLink={link}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
            />
          )}
        />
        <Route
          path="/incidents"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorIndividual.id}
              relationshipTypes={['attributed-to']}
              stixCoreObjectTypes={['Incident']}
              entityLink={link}
              isRelationReversed={true}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
            />
          )}
        />
        <Route
          path="/indicators"
          element={(
            <EntityStixCoreRelationshipsIndicators
              entityId={threatActorIndividual.id}
              entityLink={link}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
            />
          )}
        />
        <Route
          path="/observables"
          element={(
            <EntityStixCoreRelationshipsStixCyberObservable
              entityId={threatActorIndividual.id}
              entityLink={link}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
              isRelationReversed={false}
              relationshipTypes={['related-to', 'known-as']}
            />
          )}
        />
        <Route
          path="/infrastructures"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={threatActorIndividual.id}
              relationshipTypes={['uses', 'compromises']}
              stixCoreObjectTypes={['Infrastructure']}
              entityLink={link}
              isRelationReversed={false}
              defaultStartTime={threatActorIndividual.first_seen}
              defaultStopTime={threatActorIndividual.last_seen}
            />
          )}
        />
        <Route
          path="/sightings"
          element={(
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
          )}
        />
      </Routes>
    </div>
  );
};

export default ThreatActorIndividualKnowledgeComponent;
