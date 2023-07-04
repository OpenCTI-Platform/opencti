/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Switch } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import CityPopover from './CityPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import { CityKnowledge_city$key } from './__generated__/CityKnowledge_city.graphql';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
}));

const cityKnowledgeFragment = graphql`
  fragment CityKnowledge_city on City {
    id
    name
    x_opencti_aliases
  }
`;

const CityKnowledge = ({ cityData }: { cityData: CityKnowledge_city$key }) => {
  const classes = useStyles();

  const city = useFragment<CityKnowledge_city$key>(
    cityKnowledgeFragment,
    cityData,
  );
  const link = `/dashboard/locations/cities/${city.id}/knowledge`;

  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'City'}
        disableSharing={true}
        stixDomainObject={city}
        PopoverComponent={CityPopover}
        variant="noaliases"
      />
      <Switch>
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/relations/:relationId"
          render={(routeProps: any) => (
            <StixCoreRelationship
              entityId={city.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/sightings/:sightingId"
          render={(routeProps: any) => (
            <StixSightingRelationship
              entityId={city.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/overview"
          render={(routeProps: any) => (
            <StixDomainObjectKnowledge
              stixDomainObjectId={city.id}
              stixDomainObjectType="City"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/threats"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={city.id}
              relationshipTypes={['targets']}
              isRelationReversed
              entityLink={link}
              stixCoreObjectTypes={[
                'Attack-Pattern',
                'Theat-Actor-Group',
                'Intrusion-Set',
                'Campaign',
                'Incident',
                'Malware',
                'Tool',
              ]}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/related"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={city.id}
              relationshipTypes={['related-to']}
              stixCoreObjectTypes={[
                'Theat-Actor-Group',
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
                'City',
                'Position',
              ]}
              entityLink={link}
              allDirections={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/organizations"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={city.id}
              relationshipTypes={['located-at']}
              stixCoreObjectTypes={['Organization']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/areas"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={city.id}
              relationshipTypes={['located-at']}
              stixCoreObjectTypes={['Administrative-Area']}
              entityLink={link}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/countries"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={city.id}
              relationshipTypes={['located-at']}
              stixCoreObjectTypes={['Country']}
              entityLink={link}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/regions"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={city.id}
              relationshipTypes={['located-at']}
              stixCoreObjectTypes={['Region']}
              entityLink={link}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/threat_actors"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={city.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Theat-Actor-Group']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/intrusion_sets"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={city.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Intrusion-Set']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/campaigns"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={city.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Campaign']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/incidents"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={city.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Incident']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/malwares"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={city.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Malware']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/attack_patterns"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={city.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Attack-Pattern']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/tools"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={city.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Tool']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/cities/:cityId/knowledge/observables"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={city.id}
              relationshipTypes={['related-to', 'located-at']}
              stixCoreObjectTypes={['Stix-Cyber-Observable']}
              entityLink={link}
              allDirections={true}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
      </Switch>
    </div>
  );
};

export default CityKnowledge;
