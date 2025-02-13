import React from 'react';
import { Route, Routes } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import useAuth from '../../../../utils/hooks/useAuth';
import { getRelationshipTypesForEntityType } from '../../../../utils/Relation';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import EntityStixCoreRelationshipsIndicators from '../../common/stix_core_relationships/views/indicators/EntityStixCoreRelationshipsIndicators';
import EntityStixCoreRelationshipsStixCyberObservable from '../../common/stix_core_relationships/views/stix_cyber_observable/EntityStixCoreRelationshipsStixCyberObservable';

const ToolKnowledgeFragment = graphql`
      fragment ToolKnowledge_tool on Tool {
          id
          name
          aliases
          entity_type
      }
  `;

const ToolKnowledgeComponent = ({
  toolData,
}) => {
  const tool = useFragment(
    ToolKnowledgeFragment,
    toolData,
  );
  const link = `/dashboard/arsenal/tools/${tool.id}/knowledge`;
  const { schema } = useAuth();
  const allRelationshipsTypes = getRelationshipTypesForEntityType(tool.entity_type, schema);
  return (
    <>
      <Routes>
        <Route
          path="/relations/:relationId/*"
          element={
            <StixCoreRelationship
              entityId={tool.id}
              paddingRight={true}
            />
            }
        />
        <Route
          path="/sightings/:sightingId/*"
          element={
            <StixSightingRelationship
              entityId={tool.id}
              paddingRight={true}
            />
            }
        />
        <Route
          path="/overview"
          element={
            <StixDomainObjectThreatKnowledge
              stixDomainObjectId={tool.id}
              stixDomainObjectName={tool.name}
              stixDomainObjectType="Tool"
            />
            }
        />
        <Route
          path="/all"
          element={
            <EntityStixCoreRelationships
              entityId={tool.id}
              relationshipTypes={allRelationshipsTypes}
              entityLink={link}
              defaultStartTime={tool.startTime}
              defaultStopTime={tool.stopTime}
              allDirections
            />
            }
        />
        <Route
          path="/related"
          element={
            <EntityStixCoreRelationships
              entityId={tool.id}
              relationshipTypes={['related-to']}
              entityLink={link}
              allDirections={true}
            />
            }
        />
        <Route
          path="/threats"
          element={
            <EntityStixCoreRelationships
              entityId={tool.id}
              relationshipTypes={['uses']}
              isRelationReversed={true}
              entityLink={link}
              stixCoreObjectTypes={[
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'Incident',
                'Malware',
                'Channel',
              ]}
            />
                }
        />
        <Route
          path="/threat_actors"
          element={
            <EntityStixCoreRelationships
              entityId={tool.id}
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
              entityId={tool.id}
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
              entityId={tool.id}
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
              entityId={tool.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Attack-Pattern']}
              entityLink={link}
              isRelationReversed={false}
            />
            }
        />
        <Route
          path="/malwares"
          element={
            <EntityStixCoreRelationships
              entityId={tool.id}
              relationshipTypes={['delivers', 'drops', 'uses']}
              stixCoreObjectTypes={['Malware']}
              entityLink={link}
              allDirections={true}
            />
            }
        />
        <Route
          path="/vulnerabilities"
          element={
            <EntityStixCoreRelationships
              entityId={tool.id}
              relationshipTypes={['uses', 'has', 'targets']}
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
              entityId={tool.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Incident']}
              entityLink={link}
              isRelationReversed={true}
            />
            }
        />
        <Route
          path="/indicators"
          element={
            <EntityStixCoreRelationshipsIndicators
              entityId={tool.id}
              entityLink={link}
              defaultStartTime={tool.first_seen}
              defaultStopTime={tool.last_seen}
            />
            }
        />
        <Route
          path="/observables"
          element={
            <EntityStixCoreRelationshipsStixCyberObservable
              entityId={tool.id}
              entityLink={link}
              defaultStartTime={tool.first_seen}
              defaultStopTime={tool.last_seen}
              isRelationReversed={true}
              relationshipTypes={['related-to']}
            />
            }
        />
        <Route
          path="/sightings"
          element={
            <EntityStixSightingRelationships
              entityId={tool.id}
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

export default ToolKnowledgeComponent;
