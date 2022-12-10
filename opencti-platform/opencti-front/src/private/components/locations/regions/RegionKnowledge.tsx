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
import RegionPopover from './RegionPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import { RegionKnowledge_region$key } from './__generated__/RegionKnowledge_region.graphql';
import StixCoreObjectStixCyberObservables
  from '../../observations/stix_cyber_observables/StixCoreObjectStixCyberObservables';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
}));

const regionKnowledgeFragment = graphql`
  fragment RegionKnowledge_region on Region {
    id
    name
    x_opencti_aliases
  }
`;

const RegionKnowledgeComponent = ({ regionData }: { regionData: RegionKnowledge_region$key }) => {
  const classes = useStyles();
  const region = useFragment<RegionKnowledge_region$key>(regionKnowledgeFragment, regionData);
  const link = `/dashboard/locations/regions/${region.id}/knowledge`;
  return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          disableSharing={true}
          stixDomainObject={region}
          PopoverComponent={<RegionPopover id={region.id} />}
        />
        <Switch>
          <Route
            exact
            path="/dashboard/locations/regions/:regionId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={region.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/locations/regions/:regionId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={region.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/locations/regions/:regionId/knowledge/overview"
            render={(routeProps) => (
              <StixDomainObjectKnowledge
                stixDomainObjectId={region.id}
                stixDomainObjectType="Region"
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/locations/regions/:regionId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={region.id}
                relationshipTypes={['related-to']}
                targetStixDomainObjectTypes={[
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
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/locations/regions/:regionId/knowledge/countries"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={region.id}
                relationshipTypes={['located-at']}
                targetStixDomainObjectTypes={['Country']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/locations/regions/:regionId/knowledge/cities"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={region.id}
                relationshipTypes={['located-at']}
                targetStixDomainObjectTypes={['City']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/locations/regions/:regionId/knowledge/threat_actors"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={region.id}
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Threat-Actor']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/locations/regions/:regionId/knowledge/intrusion_sets"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={region.id}
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Intrusion-Set']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/locations/regions/:regionId/knowledge/campaigns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={region.id}
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Campaign']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/locations/regions/:regionId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={region.id}
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Incident']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/locations/regions/:regionId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={region.id}
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Malware']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/locations/regions/:regionId/knowledge/attack_patterns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={region.id}
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Attack-Pattern']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/locations/regions/:regionId/knowledge/tools"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={region.id}
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Tool']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/locations/regions/:regionId/knowledge/observables"
            render={(routeProps) => (
              <StixCoreObjectStixCyberObservables
                stixCoreObjectId={region.id}
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Observables']}
                stixCoreObjectLink={link}
                isRelationReversed={true}
                noRightBar={true}
                {...routeProps}
              />
            )}
          />
        </Switch>
      </div>
  );
};

export default RegionKnowledgeComponent;
