import React from 'react';
import PropTypes from 'prop-types';
import { Route, Routes, useLocation } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import useAuth from '../../../../utils/hooks/useAuth';
import { getRelationshipTypesForEntityType } from '../../../../utils/Relation';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';
import EntityStixCoreRelationshipsIndicators from '../../common/stix_core_relationships/views/indicators/EntityStixCoreRelationshipsIndicators';
import EntityStixCoreRelationshipsStixCyberObservable from '../../common/stix_core_relationships/views/stix_cyber_observable/EntityStixCoreRelationshipsStixCyberObservable';

const AttackPatternKnowledgeFragment = graphql`
  fragment AttackPatternKnowledge_attackPattern on AttackPattern {
    id
    name
    aliases
    entity_type
  }
`;

const AttackPatternKnowledgeComponent = ({
  attackPatternData,
}) => {
  const attackPattern = useFragment(
    AttackPatternKnowledgeFragment,
    attackPatternData,
  );
  const location = useLocation();
  const link = `/dashboard/techniques/attack_patterns/${attackPattern.id}/knowledge`;
  const { schema } = useAuth();
  const allRelationshipsTypes = getRelationshipTypesForEntityType(attackPattern.entity_type, schema);
  return (
    <>
      <Routes>
        <Route
          path="/relations/:relationId"
          element={
            <StixCoreRelationship entityId={attackPattern.id} paddingRight />
            }
        />
        <Route
          path="/sightings/:sightingId"
          element={
            <StixSightingRelationship entityId={attackPattern.id} />
            }
        />
        <Route
          path="/overview"
          element={
            <StixDomainObjectKnowledge
              stixDomainObjectId={attackPattern.id}
              stixDomainObjectType="Attack-Pattern"
            />
            }
        />
        <Route
          path="/all"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={attackPattern.id}
              relationshipTypes={allRelationshipsTypes}
              entityLink={link}
              defaultStartTime={attackPattern.startTime}
              defaultStopTime={attackPattern.stopTime}
              allDirections
            />
            }
        />
        <Route
          path="/related"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={attackPattern.id}
              relationshipTypes={['related-to']}
              stixCoreObjectTypes={[
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'Incident',
                'Malware',
                'Tool',
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
          path="/victimology"
          element={
            <StixDomainObjectVictimology
              stixDomainObjectId={attackPattern.id}
              entityLink={link}
            />
            }
        />
        <Route
          path="/threat_actors"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={attackPattern.id}
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
              key={location.pathname}
              entityId={attackPattern.id}
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
              key={location.pathname}
              entityId={attackPattern.id}
              relationshipTypes={['uses']}
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
              entityId={attackPattern.id}
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
              entityId={attackPattern.id}
              entityLink={link}
              defaultStartTime={attackPattern.first_seen}
              defaultStopTime={attackPattern.last_seen}
            />
            }
        />
        <Route
          path="/observables"
          element={
            <EntityStixCoreRelationshipsStixCyberObservable
              entityId={attackPattern.id}
              entityLink={link}
              defaultStartTime={attackPattern.first_seen}
              defaultStopTime={attackPattern.last_seen}
              isRelationReversed={true}
              relationshipTypes={['related-to']}
            />
            }
        />
        <Route
          path="/malwares"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={attackPattern.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Malware']}
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
              entityId={attackPattern.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Tool']}
              entityLink={link}
              isRelationReversed={true}
            />
            }
        />
        <Route
          path="/vulnerabilities"
          element={
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={attackPattern.id}
              relationshipTypes={['targets']}
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

AttackPatternKnowledgeComponent.propTypes = {
  attackPattern: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default AttackPatternKnowledgeComponent;
