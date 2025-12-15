// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import EntityStixCoreRelationshipsIndicators from '@components/common/stix_core_relationships/views/indicators/EntityStixCoreRelationshipsIndicators';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';
import StixSightingRelationship from '../stix_sighting_relationships/StixSightingRelationship';
import { IncidentKnowledge_incident$key } from './__generated__/IncidentKnowledge_incident.graphql';
import useAuth from '../../../../utils/hooks/useAuth';
import { getRelationshipTypesForEntityType } from '../../../../utils/Relation';

const IncidentKnowledgeFragment = graphql`
  fragment IncidentKnowledge_incident on Incident {
    id
    name
    aliases
    first_seen
    last_seen
    entity_type
  }
`;

const IncidentKnowledge = ({
  incidentData,
}: {
  incidentData: IncidentKnowledge_incident$key;
}) => {
  const incident = useFragment<IncidentKnowledge_incident$key>(
    IncidentKnowledgeFragment,
    incidentData,
  );
  const location = useLocation();
  const link = `/dashboard/events/incidents/${incident.id}/knowledge`;
  const { schema } = useAuth();
  const allRelationshipsTypes = getRelationshipTypesForEntityType(incident.entity_type, schema);
  return (
    <div data-testid="incident-knowledge">
      <Routes>
        <Route
          path="/relations/:relationId"
          element={(
            <StixCoreRelationship
              entityId={incident.id}
              paddingRight={true}
            />
          )}
        />
        <Route
          path="/sightings/:sightingId"
          element={(
            <StixSightingRelationship
              entityId={incident.id}
              paddingRight={true}
            />
          )}
        />
        <Route
          path="/overview"
          element={(
            <StixDomainObjectThreatKnowledge
              stixDomainObjectId={incident.id}
              stixDomainObjectName={incident.name}
              stixDomainObjectType="Incident"
              displayObservablesStats={true}
            />
          )}
        />
        <Route
          path="/all"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={incident.id}
              relationshipTypes={allRelationshipsTypes}
              entityLink={link}
              defaultStartTime={incident.startTime}
              defaultStopTime={incident.stopTime}
              allDirections
            />
          )}
        />
        <Route
          path="/related"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={incident.id}
              relationshipTypes={['related-to']}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              allDirections={true}
            />
          )}
        />
        <Route
          path="/attribution"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={incident.id}
              relationshipTypes={['attributed-to']}
              stixCoreObjectTypes={[
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
              ]}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              isRelationReversed={false}
            />
          )}
        />
        <Route
          path="/victimology"
          element={(
            <StixDomainObjectVictimology
              stixDomainObjectId={incident.id}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
            />
          )}
        />
        <Route
          path="/attack_patterns"
          element={(
            <StixDomainObjectAttackPatterns
              stixDomainObjectId={incident.id}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              disableExport={undefined}
              entityType={incident.entity_type}
            />
          )}
        />
        <Route
          path="/malwares"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={incident.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Malware']}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              isRelationReversed={false}
            />
          )}
        />
        <Route
          path="/narratives"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={incident.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Narrative']}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              isRelationReversed={false}
            />
          )}
        />
        <Route
          path="/channels"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={incident.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Channel']}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              isRelationReversed={false}
            />
          )}
        />
        <Route
          path="/tools"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={incident.id}
              relationshipTypes={['uses']}
              stixCoreObjectTypes={['Tool']}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              isRelationReversed={false}
            />
          )}
        />
        <Route
          path="/vulnerabilities"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={incident.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Vulnerability']}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              isRelationReversed={false}
            />
          )}
        />
        <Route
          path="/indicators"
          element={(
            <EntityStixCoreRelationshipsIndicators
              entityId={incident.id}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
            />
          )}
        />
        <Route
          path="/observables"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={incident.id}
              relationshipTypes={['related-to']}
              stixCoreObjectTypes={['Stix-Cyber-Observable']}
              entityLink={link}
              defaultStartTime={incident.first_seen}
              defaultStopTime={incident.last_seen}
              allDirections={true}
              isRelationReversed={true}
            />
          )}
        />
      </Routes>
    </div>
  );
};

export default IncidentKnowledge;
