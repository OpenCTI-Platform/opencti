// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Routes } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import { CountryKnowledge_country$key } from './__generated__/CountryKnowledge_country.graphql';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';

const countryKnowledgeFragment = graphql`
  fragment CountryKnowledge_country on Country {
    id
    name
    x_opencti_aliases
  }
`;

const CountryKnowledgeComponent = ({
  countryData,
}: {
  countryData: CountryKnowledge_country$key;
}) => {
  const country = useFragment<CountryKnowledge_country$key>(
    countryKnowledgeFragment,
    countryData,
  );
  const link = `/dashboard/locations/countries/${country.id}/knowledge`;
  return (
    <>
      <Routes>
        <Route
          path="/relations/:relationId"
          element={
            <StixCoreRelationship
              entityId={country.id}
              paddingRight={20}
            />
          }
        />
        <Route
          path="/sightings/:sightingId"
          element={
            <StixSightingRelationship
              entityId={country.id}
              paddingRight={true}
            />
          }
        />
        <Route
          path="/overview"
          element={
            <StixDomainObjectKnowledge
              stixDomainObjectId={country.id}
              stixDomainObjectType="Country"
            />
          }
        />
        <Route
          path="/threats"
          element={
            <EntityStixCoreRelationships
              entityId={country.id}
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
              entityId={country.id}
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
          path="/regions"
          element={
            <EntityStixCoreRelationships
              entityId={country.id}
              relationshipTypes={['located-at']}
              stixCoreObjectTypes={['Region']}
              entityLink={link}
              isRelationReversed={false}
            />
          }
        />
        <Route
          path="/areas"
          element={
            <EntityStixCoreRelationships
              entityId={country.id}
              relationshipTypes={['located-at']}
              stixCoreObjectTypes={['Administrative-Area']}
              entityLink={link}
              isRelationReversed={true}
            />
          }
        />
        <Route
          path="/cities"
          element={
            <EntityStixCoreRelationships
              entityId={country.id}
              relationshipTypes={['located-at']}
              stixCoreObjectTypes={['City']}
              entityLink={link}
              isRelationReversed={true}
            />
          }
        />
        <Route
          path="/organizations"
          element={
            <EntityStixCoreRelationships
              entityId={country.id}
              relationshipTypes={['located-at']}
              stixCoreObjectTypes={['Organization']}
              entityLink={link}
              isRelationReversed={true}
            />
          }
        />
        <Route
          path="/threat_actors"
          element={
            <EntityStixCoreRelationships
              entityId={country.id}
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
              entityId={country.id}
              relationshipTypes={['targets', 'originates-from']}
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
              entityId={country.id}
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
              entityId={country.id}
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
              entityId={country.id}
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
              entityId={country.id}
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
              entityId={country.id}
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
              entityId={country.id}
              relationshipTypes={['related-to', 'located-at']}
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
              entityId={country.id}
              entityLink={link}
              noRightBar={true}
              isTo={true}
            />
          }
        />
      </Routes>
    </>
  );
};

export default CountryKnowledgeComponent;
