import React from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import useAuth from '../../../../utils/hooks/useAuth';
import { getRelationshipTypesForEntityType } from '../../../../utils/Relation';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixDomainObjectAuthorKnowledge from '../../common/stix_domain_objects/StixDomainObjectAuthorKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const systemKnowledgeFragment = graphql`
  fragment SystemKnowledge_system on System {
    id
    name
    x_opencti_aliases
    entity_type
  }
`;

const SystemKnowledgeComponent = ({
  systemData,
  viewAs,
}) => {
  const system = useFragment(
    systemKnowledgeFragment,
    systemData,
  );
  const location = useLocation();
  const link = `/dashboard/entities/systems/${system.id}/knowledge`;
  const { schema } = useAuth();
  const allRelationshipsTypes = getRelationshipTypesForEntityType(system.entity_type, schema);
  return (
    <>
      <Routes>
        <Route
          path="/relations/:relationId"
          element={
            <StixCoreRelationship
              entityId={system.id}
              paddingRight={true}
            />
            }
        />
        <Route
          path="/sightings/:sightingId"
          element={
            <StixSightingRelationship
              entityId={system.id}
              paddingRight={true}
            />
            }
        />
        <Route
          path="/overview"
          element={(viewAs === 'knowledge' ? (
            <StixDomainObjectKnowledge
              stixDomainObjectId={system.id}
              stixDomainObjectType="System"
            />
          ) : (
            <StixDomainObjectAuthorKnowledge
              stixDomainObjectId={system.id}
              stixDomainObjectType="System"
            />
          ))
            }
        />
        <Route
          path="/all"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={system.id}
              relationshipTypes={allRelationshipsTypes}
              entityLink={link}
              defaultStartTime={system.startTime}
              defaultStopTime={system.stopTime}
              allDirections
            />
            }
        />
        <Route
          path="/threats"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={system.id}
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
              entityId={system.id}
              relationshipTypes={['related-to']}
              entityLink={link}
              allDirections={true}
            />
            }
        />
        <Route
          path="/systems"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={system.id}
              relationshipTypes={['part-of']}
              stixCoreObjectTypes={['System']}
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
              entityId={system.id}
              relationshipTypes={['localization']}
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
              entityId={system.id}
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
              entityId={system.id}
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
              entityId={system.id}
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
              entityId={system.id}
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
              entityId={system.id}
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
              entityId={system.id}
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
              entityId={system.id}
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
              entityId={system.id}
              relationshipTypes={['related-to']}
              stixCoreObjectTypes={['Stix-Cyber-Observable']}
              entityLink={link}
              allDirections={true}
              isRelationReversed={true}
            />
            }
        />
        <Route
          path="/sightings"
          element={
            <EntityStixSightingRelationships
              entityId={system.id}
              entityLink={link}
              noRightBar={true}
              isTo={true}
            />
            }
        />
        <Route
          path="/vulnerabilities"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={system.id}
              relationshipTypes={['has']}
              stixCoreObjectTypes={['Vulnerability']}
              entityLink={link}
              isRelationReversed={false}
            />
            }
        />
      </Routes>
    </>
  );
};

export default SystemKnowledgeComponent;
