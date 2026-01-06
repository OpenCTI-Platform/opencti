// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import { AdministrativeAreaKnowledge_administrativeArea$key } from './__generated__/AdministrativeAreaKnowledge_administrativeArea.graphql';
import useAuth from '../../../../utils/hooks/useAuth';
import { getRelationshipTypesForEntityType } from '../../../../utils/Relation';

const administrativeAreaKnowledgeFragment = graphql`
  fragment AdministrativeAreaKnowledge_administrativeArea on AdministrativeArea {
    id
    name
    x_opencti_aliases
    entity_type
  }
`;

const AdministrativeAreaKnowledge = ({
  administrativeAreaData,
}: {
  administrativeAreaData: AdministrativeAreaKnowledge_administrativeArea$key;
}) => {
  const administrativeArea = useFragment<AdministrativeAreaKnowledge_administrativeArea$key>(
    administrativeAreaKnowledgeFragment,
    administrativeAreaData,
  );
  const location = useLocation();
  const link = `/dashboard/locations/administrative_areas/${administrativeArea.id}/knowledge`;
  const { schema } = useAuth();
  const allRelationshipsTypes = getRelationshipTypesForEntityType(administrativeArea.entity_type, schema);
  return (
    <div data-testid="administrative-area-knowledge">
      <Routes>
        <Route
          path="/relations/:relationId"
          element={(
            <StixCoreRelationship
              entityId={administrativeArea.id}
              paddingRight={true}
            />
          )}
        />
        <Route
          path="/sightings/:sightingId"
          element={(
            <StixSightingRelationship
              entityId={administrativeArea.id}
              paddingRight={true}
            />
          )}
        />
        <Route
          path="/overview"
          element={(
            <StixDomainObjectKnowledge
              stixDomainObjectId={administrativeArea.id}
              stixDomainObjectType="Administrative-Area"
            />
          )}
        />
        <Route
          path="/all"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={administrativeArea.id}
              relationshipTypes={allRelationshipsTypes}
              entityLink={link}
              defaultStartTime={administrativeArea.startTime}
              defaultStopTime={administrativeArea.stopTime}
              allDirections
            />
          )}
        />
        <Route
          path="/threats"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={administrativeArea.id}
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
          )}
        />
        <Route
          path="/related"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={administrativeArea.id}
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
                'Administrative-Area',
                'Position',
              ]}
              entityLink={link}
              allDirections={true}
            />
          )}
        />
        <Route
          path="/organizations"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={administrativeArea.id}
              relationshipTypes={['located-at']}
              stixCoreObjectTypes={['Organization']}
              entityLink={link}
              isRelationReversed={true}
            />
          )}
        />
        <Route
          path="/regions"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={administrativeArea.id}
              relationshipTypes={['located-at']}
              stixCoreObjectTypes={['Region']}
              entityLink={link}
              isRelationReversed={false}
            />
          )}
        />
        <Route
          path="/countries"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={administrativeArea.id}
              relationshipTypes={['located-at']}
              stixCoreObjectTypes={['Country']}
              entityLink={link}
              isRelationReversed={false}
            />
          )}
        />
        <Route
          path="/cities"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={administrativeArea.id}
              relationshipTypes={['located-at']}
              stixCoreObjectTypes={['City']}
              entityLink={link}
              isRelationReversed={true}
            />
          )}
        />
        <Route
          path="/threat_actors"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={administrativeArea.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Threat-Actor']}
              entityLink={link}
              isRelationReversed={true}
            />
          )}
        />
        <Route
          path="/intrusion_sets"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={administrativeArea.id}
              relationshipTypes={['targets', 'originates-from']}
              stixCoreObjectTypes={['Intrusion-Set']}
              entityLink={link}
              isRelationReversed={true}
            />
          )}
        />
        <Route
          path="/campaigns"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={administrativeArea.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Campaign']}
              entityLink={link}
              isRelationReversed={true}
            />
          )}
        />
        <Route
          path="/incidents"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={administrativeArea.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Incident']}
              entityLink={link}
              isRelationReversed={true}
            />
          )}
        />
        <Route
          path="/malwares"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={administrativeArea.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Malware']}
              entityLink={link}
              isRelationReversed={true}
            />
          )}
        />
        <Route
          path="/attack_patterns"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={administrativeArea.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Attack-Pattern']}
              entityLink={link}
              isRelationReversed={true}
            />
          )}
        />
        <Route
          path="/tools"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={administrativeArea.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Tool']}
              entityLink={link}
              isRelationReversed={true}
            />
          )}
        />
        <Route
          path="/observables"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={administrativeArea.id}
              relationshipTypes={['related-to', 'located-at']}
              stixCoreObjectTypes={['Stix-Cyber-Observable']}
              entityLink={link}
              allDirections={true}
              isRelationReversed={true}
            />
          )}
        />
      </Routes>
    </div>
  );
};

export default AdministrativeAreaKnowledge;
