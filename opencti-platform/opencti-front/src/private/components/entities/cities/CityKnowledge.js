import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import CityPopover from './CityPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixCoreObjectStixCyberObservables from '../../observations/stix_cyber_observables/StixCoreObjectStixCyberObservables';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class CityKnowledgeComponent extends Component {
  render() {
    const { classes, city } = this.props;
    const link = `/dashboard/entities/cities/${city.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={city}
          PopoverComponent={<CityPopover />}
          variant="noaliases"
        />
        <Switch>
          <Route
            exact
            path="/dashboard/entities/cities/:cityId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={city.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/cities/:cityId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={city.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/cities/:cityId/knowledge/overview"
            render={(routeProps) => (
              <StixDomainObjectKnowledge
                stixDomainObjectId={city.id}
                stixDomainObjectType="City"
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/cities/:cityId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={city.id}
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
            path="/dashboard/entities/cities/:cityId/knowledge/organizations"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={city.id}
                relationshipTypes={['located-at']}
                targetStixDomainObjectTypes={['Organization']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/cities/:cityId/knowledge/countries"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={city.id}
                relationshipTypes={['located-at']}
                targetStixDomainObjectTypes={['Country']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/cities/:cityId/knowledge/threat_actors"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={city.id}
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
            path="/dashboard/entities/cities/:cityId/knowledge/intrusion_sets"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={city.id}
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
            path="/dashboard/entities/cities/:cityId/knowledge/campaigns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={city.id}
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
            path="/dashboard/entities/cities/:cityId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={city.id}
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
            path="/dashboard/entities/cities/:cityId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={city.id}
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
            path="/dashboard/entities/cities/:cityId/knowledge/attack_patterns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={city.id}
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
            path="/dashboard/entities/cities/:cityId/knowledge/tools"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={city.id}
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
            path="/dashboard/entities/cities/:cityId/knowledge/observables"
            render={(routeProps) => (
              <StixCoreObjectStixCyberObservables
                stixCoreObjectId={city.id}
                stixCoreObjectLink={link}
                noRightBar={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/cities/:cityId/knowledge/sightings"
            render={(routeProps) => (
              <EntityStixSightingRelationships
                entityId={city.id}
                entityLink={link}
                noRightBar={true}
                isTo={true}
                {...routeProps}
              />
            )}
          />
        </Switch>
      </div>
    );
  }
}

CityKnowledgeComponent.propTypes = {
  city: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const CityKnowledge = createFragmentContainer(CityKnowledgeComponent, {
  city: graphql`
    fragment CityKnowledge_city on City {
      id
      name
      x_opencti_aliases
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(CityKnowledge);
