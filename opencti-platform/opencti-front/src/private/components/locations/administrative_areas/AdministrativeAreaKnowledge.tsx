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
import AdministrativeAreaPopover from './AdministrativeAreaPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import { AdministrativeAreaKnowledge_administrativeArea$key } from './__generated__/AdministrativeAreaKnowledge_administrativeArea.graphql';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
}));

const administrativeAreaKnowledgeFragment = graphql`
  fragment AdministrativeAreaKnowledge_administrativeArea on AdministrativeArea {
    id
    name
    x_opencti_aliases
  }
`;

const AdministrativeAreaKnowledge = ({
  administrativeAreaData,
}: {
  administrativeAreaData: AdministrativeAreaKnowledge_administrativeArea$key;
}) => {
  const classes = useStyles();

  const administrativeArea = useFragment<AdministrativeAreaKnowledge_administrativeArea$key>(
    administrativeAreaKnowledgeFragment,
    administrativeAreaData,
  );
  const link = `/dashboard/locations/administrative_areas/${administrativeArea.id}/knowledge`;

  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Administrative-Area'}
        disableSharing={true}
        stixDomainObject={administrativeArea}
        PopoverComponent={AdministrativeAreaPopover}
        variant="noaliases"
      />
      <Switch>
        <Route
          exact
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/relations/:relationId"
          render={(routeProps: any) => (
            <StixCoreRelationship
              entityId={administrativeArea.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/sightings/:sightingId"
          render={(routeProps: any) => (
            <StixSightingRelationship
              entityId={administrativeArea.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/overview"
          render={(routeProps: any) => (
            <StixDomainObjectKnowledge
              stixDomainObjectId={administrativeArea.id}
              stixDomainObjectType="Administrative-Area"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/threats"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
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
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/related"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
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
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/organizations"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={administrativeArea.id}
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
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/regions"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={administrativeArea.id}
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
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/countries"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={administrativeArea.id}
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
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/cities"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={administrativeArea.id}
              relationshipTypes={['located-at']}
              stixCoreObjectTypes={['City']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/threat_actors"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={administrativeArea.id}
              relationshipTypes={['targets']}
              stixCoreObjectTypes={['Threat-Actor']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/intrusion_sets"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={administrativeArea.id}
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
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/campaigns"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={administrativeArea.id}
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
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/incidents"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={administrativeArea.id}
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
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/malwares"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={administrativeArea.id}
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
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/attack_patterns"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={administrativeArea.id}
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
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/tools"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={administrativeArea.id}
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
          path="/dashboard/locations/administrative_areas/:administrativeAreaId/knowledge/observables"
          render={(routeProps: any) => (
            <EntityStixCoreRelationships
              entityId={administrativeArea.id}
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

export default AdministrativeAreaKnowledge;
