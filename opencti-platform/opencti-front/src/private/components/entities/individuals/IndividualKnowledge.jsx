import React from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import useAuth from '../../../../utils/hooks/useAuth';
import { getRelationshipTypesForEntityType } from '../../../../utils/Relation';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectAuthorKnowledge from '../../common/stix_domain_objects/StixDomainObjectAuthorKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const individualKnowledgeFragment = graphql`
  fragment IndividualKnowledge_individual on Individual {
    id
    name
    x_opencti_aliases
    entity_type
  }
`;

const IndividualKnowledgeComponent = ({
  individualData,
  viewAs,
}) => {
  const individual = useFragment(
    individualKnowledgeFragment,
    individualData,
  );
  const location = useLocation();
  const link = `/dashboard/entities/individuals/${individual.id}/knowledge`;
  const { schema } = useAuth();
  const allRelationshipsTypes = getRelationshipTypesForEntityType(individual.entity_type, schema);
  return (
    <Routes>
      <Route
        path="/relations/:relationId"
        element={
          <StixCoreRelationship
            entityId={individual.id}
            paddingRight={true}
          />
        }
      />
      <Route
        path="/sightings/:sightingId"
        element={
          <StixSightingRelationship
            entityId={individual.id}
            paddingRight={true}
          />
        }
      />
      <Route
        path="/overview"
        element={(viewAs === 'knowledge' ? (
          <StixDomainObjectKnowledge
            stixDomainObjectId={individual.id}
            stixDomainObjectType="Individual"
          />
        ) : (
          <StixDomainObjectAuthorKnowledge
            stixDomainObjectId={individual.id}
            stixDomainObjectType="Individual"
          />
        ))
          }
      />
      <Route
        path="/all"
        element={
          <EntityStixCoreRelationships
            key={location.pathname}
            entityId={individual.id}
            relationshipTypes={allRelationshipsTypes}
            entityLink={link}
            defaultStartTime={individual.startTime}
            defaultStopTime={individual.stopTime}
            allDirections
          />
        }
      />
      <Route
        path="/threats"
        element={
          <EntityStixCoreRelationships
            key={location.pathname}
            entityId={individual.id}
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
            key={location.pathname}
            entityId={individual.id}
            relationshipTypes={['related-to']}
            entityLink={link}
            allDirections={true}
          />
        }
      />
      <Route
        path="/organizations"
        element={
          <EntityStixCoreRelationships
            key={location.pathname}
            entityId={individual.id}
            relationshipTypes={['part-of']}
            stixCoreObjectTypes={['Organization']}
            entityLink={link}
            isRelationReversed={false}
          />
        }
      />
      <Route
        path="/locations"
        element={
          <EntityStixCoreRelationships
            key={location.pathname}
            entityId={individual.id}
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
            key={location.pathname}
            entityId={individual.id}
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
            key={location.pathname}
            entityId={individual.id}
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
            key={location.pathname}
            entityId={individual.id}
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
            key={location.pathname}
            entityId={individual.id}
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
            key={location.pathname}
            entityId={individual.id}
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
            key={location.pathname}
            entityId={individual.id}
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
            key={location.pathname}
            entityId={individual.id}
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
            key={location.pathname}
            entityId={individual.id}
            relationshipTypes={['related-to']}
            stixCoreObjectTypes={['Stix-Cyber-Observable']}
            entityLink={link}
            allDirections={true}
            isRelationReversed={true}
          />
        }
      />
    </Routes>
  );
};

export default IndividualKnowledgeComponent;
