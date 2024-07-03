/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Routes } from 'react-router-dom';
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

const infrastructureKnowledgeFragment = graphql`
  fragment InfrastructureKnowledge_infrastructure on Infrastructure {
    id
    name
    aliases
    first_seen
    last_seen
  }
`;

const InfrastructureKnowledge = ({ infrastructure }: { infrastructure: InfrastructureKnowledge_infrastructure$key }) => {
  const infrastructureData = useFragment<InfrastructureKnowledge_infrastructure$key>(
    infrastructureKnowledgeFragment,
    infrastructure,
  );
  const link = `/dashboard/observations/infrastructures/${infrastructureData.id}/knowledge`;
  return (
    <>
      <StixCoreObjectKnowledgeBar
        stixCoreObjectLink={link}
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
          element={
            <StixCoreRelationship
              entityId={infrastructureData.id}
              paddingRight={true}
            />
          }
        />
        <Route
          path="/sightings/:sightingId/"
          element={
            <StixSightingRelationship
              entityId={infrastructureData.id}
              paddingRight={true}
            />
          }
        />
        <Route
          path="/overview"
          element={
            <StixDomainObjectThreatKnowledge
              stixDomainObjectId={infrastructureData.id}
              stixDomainObjectName={infrastructureData.name}
              stixDomainObjectType="Infrastructure"
            />
        }
        />
        <Route
          path="/related"
          element={
            <EntityStixCoreRelationships
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
        }
        />
        <Route
          path="/infrastructures"
          element={
            <EntityStixCoreRelationships
              entityId={infrastructureData.id}
              relationshipTypes={[
                'communicates-with',
                'consists-of',
                'controls',
                'uses',
              ]}
              stixCoreObjectTypes={['Infrastructure']}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
            />
        }
        />
        <Route
          path="/indicators"
          element={
            <EntityStixCoreRelationshipsIndicators
              entityId={infrastructureData.id}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
            />
        }
        />
        <Route
          path="/observables"
          element={
            <EntityStixCoreRelationshipsStixCyberObservable
              entityId={infrastructureData.id}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
              relationshipTypes={['communicates-with', 'consists-of', 'related-to']}
            />
        }
        />
        <Route
          path="/observed_data"
          element={
            <EntityStixCoreRelationships
              entityId={infrastructureData.id}
              stixCoreObjectTypes={['Observed-Data']}
              relationshipTypes={['consists-of']}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
              isRelationReversed={false}
            />
        }
        />
        <Route
          path="/threats"
          element={
            <EntityStixCoreRelationships
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
        }
        />
        <Route
          path="/threat_actors"
          element={
            <EntityStixCoreRelationships
              entityId={infrastructureData.id}
              stixCoreObjectTypes={['Threat-Actor']}
              relationshipTypes={['compromises', 'uses']}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
              isRelationReversed={true}
            />
        }
        />
        <Route
          path="/intrusion_sets"
          element={
            <EntityStixCoreRelationships
              entityId={infrastructureData.id}
              stixCoreObjectTypes={['Intrusion-Set']}
              relationshipTypes={['compromises', 'uses']}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
              isRelationReversed={true}
            />
        }
        />
        <Route
          path="/campaigns"
          element={
            <EntityStixCoreRelationships
              entityId={infrastructureData.id}
              stixCoreObjectTypes={['Campaign']}
              relationshipTypes={['compromises', 'uses']}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
              isRelationReversed={true}
            />
        }
        />
        <Route
          path="/malwares"
          element={
            <EntityStixCoreRelationships
              entityId={infrastructureData.id}
              stixCoreObjectTypes={['Malware']}
              relationshipTypes={['controls', 'delivers', 'hosts']}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
            />
        }
        />
        <Route
          path="/tools"
          element={
            <EntityStixCoreRelationships
              entityId={infrastructureData.id}
              stixCoreObjectTypes={['Tool']}
              relationshipTypes={['hosts']}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
            />
        }
        />
        <Route
          path="/vulnerabilities"
          element={
            <EntityStixCoreRelationships
              entityId={infrastructureData.id}
              relationshipTypes={['has']}
              stixCoreObjectTypes={['Vulnerability']}
              entityLink={link}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
            />
        }
        />
        <Route
          path="/sightings"
          element={
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
        }
        />
        <Route
          path="/incidents"
          element={
            <EntityStixCoreRelationships
              entityId={infrastructureData.id}
              relationshipTypes={['uses', 'compromises']}
              stixCoreObjectTypes={['Incident']}
              entityLink={link}
              isRelationReversed={true}
              defaultStartTime={infrastructureData.first_seen}
              defaultStopTime={infrastructureData.last_seen}
            />
          }
        />
      </Routes>
    </>
  );
};

export default InfrastructureKnowledge;
