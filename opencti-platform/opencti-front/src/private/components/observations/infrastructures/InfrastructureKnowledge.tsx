/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
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
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/relations/:relationId"
        render={(routeProps) => (
          <StixCoreRelationship
            entityId={infrastructureData.id}
            paddingRight={true}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/sightings/:sightingId"
        render={(routeProps) => (
          <StixSightingRelationship
            entityId={infrastructureData.id}
            paddingRight={true}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/overview"
        render={(routeProps) => (
          <StixDomainObjectThreatKnowledge
            stixDomainObjectId={infrastructureData.id}
            stixDomainObjectType="Infrastructure"
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/related"
        render={(routeProps) => (
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
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/infrastructures"
        render={(routeProps) => (
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
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/indicators"
        render={(routeProps) => (
          <EntityStixCoreRelationshipsIndicators
            {...routeProps}
            entityId={infrastructureData.id}
            entityLink={link}
            defaultStartTime={infrastructureData.first_seen}
            defaultStopTime={infrastructureData.last_seen}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/observables"
        render={(routeProps) => (
          <EntityStixCoreRelationshipsStixCyberObservable
            {...routeProps}
            entityId={infrastructureData.id}
            entityLink={link}
            defaultStartTime={infrastructureData.first_seen}
            defaultStopTime={infrastructureData.last_seen}
            relationshipTypes={['communicates-with', 'consists-of', 'related-to']}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/observed_data"
        render={(routeProps) => (
          <EntityStixCoreRelationships
            entityId={infrastructureData.id}
            stixCoreObjectTypes={['Observed-Data']}
            relationshipTypes={['consists-of']}
            entityLink={link}
            defaultStartTime={infrastructureData.first_seen}
            defaultStopTime={infrastructureData.last_seen}
            isRelationReversed={false}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/threats"
        render={(routeProps) => (
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
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/threat_actors"
        render={(routeProps) => (
          <EntityStixCoreRelationships
            entityId={infrastructureData.id}
            stixCoreObjectTypes={['Threat-Actor']}
            relationshipTypes={['compromises', 'uses']}
            entityLink={link}
            defaultStartTime={infrastructureData.first_seen}
            defaultStopTime={infrastructureData.last_seen}
            isRelationReversed={true}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/intrusion_sets"
        render={(routeProps) => (
          <EntityStixCoreRelationships
            entityId={infrastructureData.id}
            stixCoreObjectTypes={['Intrusion-Set']}
            relationshipTypes={['compromises', 'uses']}
            entityLink={link}
            defaultStartTime={infrastructureData.first_seen}
            defaultStopTime={infrastructureData.last_seen}
            isRelationReversed={true}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/campaigns"
        render={(routeProps) => (
          <EntityStixCoreRelationships
            entityId={infrastructureData.id}
            stixCoreObjectTypes={['Campaign']}
            relationshipTypes={['compromises', 'uses']}
            entityLink={link}
            defaultStartTime={infrastructureData.first_seen}
            defaultStopTime={infrastructureData.last_seen}
            isRelationReversed={true}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/malwares"
        render={(routeProps) => (
          <EntityStixCoreRelationships
            entityId={infrastructureData.id}
            stixCoreObjectTypes={['Malware']}
            relationshipTypes={['controls', 'delivers', 'hosts']}
            entityLink={link}
            defaultStartTime={infrastructureData.first_seen}
            defaultStopTime={infrastructureData.last_seen}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/tools"
        render={(routeProps) => (
          <EntityStixCoreRelationships
            entityId={infrastructureData.id}
            stixCoreObjectTypes={['Tool']}
            relationshipTypes={['hosts']}
            entityLink={link}
            defaultStartTime={infrastructureData.first_seen}
            defaultStopTime={infrastructureData.last_seen}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/vulnerabilities"
        render={(routeProps) => (
          <EntityStixCoreRelationships
            entityId={infrastructureData.id}
            relationshipTypes={['has']}
            stixCoreObjectTypes={['Vulnerability']}
            entityLink={link}
            defaultStartTime={infrastructureData.first_seen}
            defaultStopTime={infrastructureData.last_seen}
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/sightings"
        render={(routeProps) => (
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
            {...routeProps}
          />
        )}
      />
      <Route
        exact
        path="/dashboard/observations/infrastructures/:infrastructureId/knowledge/incidents"
        render={(routeProps) => (
          <EntityStixCoreRelationships
            entityId={infrastructureData.id}
            relationshipTypes={['uses', 'compromises']}
            stixCoreObjectTypes={['Incident']}
            entityLink={link}
            isRelationReversed={true}
            defaultStartTime={infrastructureData.first_seen}
            defaultStopTime={infrastructureData.last_seen}
            {...routeProps}
          />
        )}
      />
    </>
  );
};

export default InfrastructureKnowledge;
