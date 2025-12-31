// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import StixCoreObjectKnowledgeBar from '@components/common/stix_core_objects/StixCoreObjectKnowledgeBar';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import EntityStixCoreRelationshipsIndicators from '../../common/stix_core_relationships/views/indicators/EntityStixCoreRelationshipsIndicators';
import EntityStixCoreRelationshipsStixCyberObservable from '../../common/stix_core_relationships/views/stix_cyber_observable/EntityStixCoreRelationshipsStixCyberObservable';
import { InfrastructureKnowledge_infrastructure$key } from './__generated__/InfrastructureKnowledge_infrastructure.graphql';
import useAuth from '../../../../utils/hooks/useAuth';
import { getRelationshipTypesForEntityType } from '../../../../utils/Relation';

const infrastructureKnowledgeFragment = graphql`
  fragment InfrastructureKnowledge_infrastructure on Infrastructure {
    id
    name
    aliases
    first_seen
    last_seen
    entity_type
    ...StixCoreObjectKnowledgeBar_stixCoreObject
  }
`;

const InfrastructureKnowledge = ({ infrastructure }: { infrastructure: InfrastructureKnowledge_infrastructure$key }) => {
  const infrastructureData = useFragment<InfrastructureKnowledge_infrastructure$key>(
    infrastructureKnowledgeFragment,
    infrastructure,
  );
  const location = useLocation();
  const link = `/dashboard/observations/infrastructures/${infrastructureData.id}/knowledge`;
  const { schema } = useAuth();
  const allRelationshipsTypes = getRelationshipTypesForEntityType(infrastructureData.entity_type, schema);
  return (
    <div data-testid="infrastructure-knowledge">
      <StixCoreObjectKnowledgeBar
        stixCoreObjectLink={link}
        data={infrastructureData}
        availableSections={[
          'threats',
          'threat_actors',
          'intrusion_sets',
          'campaigns',
          'incidents',
          'malwares',
          'tools',
          'vulnerabilities',
          'infrastructures',
          'indicators',
          'observables',
          'observed_data',
          'sightings',
        ]}
      />
      <Routes>
        <Route
          path="/relations/:relationId/"
          element={(
            <StixCoreRelationship
              entityId={infrastructureData.id}
              paddingRight={true}
            />
          )}
        />
        <Route
          path="/sightings/:sightingId/"
          element={(
            <StixSightingRelationship
              entityId={infrastructureData.id}
              paddingRight={true}
            />
          )}
        />
        <Route
          path="/overview"
          element={(
            <StixDomainObjectThreatKnowledge
              stixDomainObjectId={infrastructureData.id}
              stixDomainObjectName={infrastructureData.name}
              stixDomainObjectType="Infrastructure"
            />
          )}
        />
        <Route
          path="/all"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={infrastructureData.id}
              relationshipTypes={allRelationshipsTypes}
              entityLink={link}
              defaultStartTime={infrastructure.startTime}
              defaultStopTime={infrastructure.stopTime}
              allDirections
            />
          )}
        />
        <Route
          path="/related"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={infrastructureData.id}
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
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
              allDirections={true}
            />
          )}
        />
        <Route
          path="/infrastructures"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={infrastructureData.id}
              relationshipTypes={[
                'communicates-with',
                'consists-of',
                'controls',
                'uses',
                'derived-from',
                'supports',
              ]}
              stixCoreObjectTypes={['Infrastructure']}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
            />
          )}
        />
        <Route
          path="/indicators"
          element={(
            <EntityStixCoreRelationshipsIndicators
              entityId={infrastructureData.id}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
            />
          )}
        />
        <Route
          path="/observables"
          element={(
            <EntityStixCoreRelationshipsStixCyberObservable
              entityId={infrastructureData.id}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
              relationshipTypes={[
                'communicates-with',
                'consists-of',
                'related-to',
                'technology-from',
                'technology-to',
                'technology',
              ]}
            />
          )}
        />
        <Route
          path="/observed_data"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={infrastructureData.id}
              stixCoreObjectTypes={['Observed-Data']}
              relationshipTypes={['consists-of']}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
              isRelationReversed={false}
            />
          )}
        />
        <Route
          path="/threats"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={infrastructureData.id}
              relationshipTypes={['compromises', 'uses']}
              entityLink={link}
              stixCoreObjectTypes={[
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'Incident',
                'Malware',
                'Tool',
              ]}
              isRelationReversed={true}
            />
          )}
        />
        <Route
          path="/threat_actors"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={infrastructureData.id}
              stixCoreObjectTypes={['Threat-Actor']}
              relationshipTypes={['compromises', 'uses']}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
              isRelationReversed={true}
            />
          )}
        />
        <Route
          path="/intrusion_sets"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={infrastructureData.id}
              stixCoreObjectTypes={['Intrusion-Set']}
              relationshipTypes={['compromises', 'uses']}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
              isRelationReversed={true}
            />
          )}
        />
        <Route
          path="/campaigns"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={infrastructureData.id}
              stixCoreObjectTypes={['Campaign']}
              relationshipTypes={['compromises', 'uses']}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
              isRelationReversed={true}
            />
          )}
        />
        <Route
          path="/malwares"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={infrastructureData.id}
              stixCoreObjectTypes={['Malware']}
              relationshipTypes={['controls', 'delivers', 'hosts', 'uses']}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
              allDirections={true}
            />
          )}
        />
        <Route
          path="/tools"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={infrastructureData.id}
              stixCoreObjectTypes={['Tool']}
              relationshipTypes={['hosts', 'uses']}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
              allDirections={true}
            />
          )}
        />
        <Route
          path="/vulnerabilities"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={infrastructureData.id}
              relationshipTypes={['has']}
              stixCoreObjectTypes={['Vulnerability']}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
            />
          )}
        />
        <Route
          path="/sightings"
          element={(
            <EntityStixSightingRelationships
              entityId={infrastructureData.id}
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
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
            />
          )}
        />
        <Route
          path="/incidents"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={infrastructureData.id}
              relationshipTypes={['uses', 'compromises']}
              stixCoreObjectTypes={['Incident']}
              entityLink={link}
              isRelationReversed={true}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
            />
          )}
        />
      </Routes>
    </div>
  );
};

export default InfrastructureKnowledge;
