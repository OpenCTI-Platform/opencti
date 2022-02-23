import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import CountryPopover from './CountryPopover';
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

class CountryKnowledgeComponent extends Component {
  render() {
    const { classes, country } = this.props;
    const link = `/dashboard/entities/countries/${country.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={country}
          PopoverComponent={<CountryPopover />}
          variant="noaliases"
        />
        <Switch>
          <Route
            exact
            path="/dashboard/entities/countries/:countryId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={country.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/countries/:countryId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={country.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/countries/:countryId/knowledge/overview"
            render={(routeProps) => (
              <StixDomainObjectKnowledge
                stixDomainObjectId={country.id}
                stixDomainObjectType="Country"
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/countries/:countryId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={country.id}
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
            path="/dashboard/entities/countries/:countryId/knowledge/cities"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={country.id}
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
            path="/dashboard/entities/countries/:countryId/knowledge/organizations"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={country.id}
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
            path="/dashboard/entities/countries/:countryId/knowledge/threat_actors"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={country.id}
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
            path="/dashboard/entities/countries/:countryId/knowledge/intrusion_sets"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={country.id}
                relationshipTypes={['targets', 'originates-from']}
                targetStixDomainObjectTypes={['Campaign', 'Intrusion-Set']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/countries/:countryId/knowledge/campaigns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={country.id}
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
            path="/dashboard/entities/countries/:countryId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={country.id}
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
            path="/dashboard/entities/countries/:countryId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={country.id}
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
            path="/dashboard/entities/countries/:countryId/knowledge/attack_patterns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={country.id}
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
            path="/dashboard/entities/countries/:countryId/knowledge/tools"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={country.id}
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
            path="/dashboard/entities/countries/:countryId/knowledge/observables"
            render={(routeProps) => (
              <StixCoreObjectStixCyberObservables
                stixCoreObjectId={country.id}
                stixCoreObjectLink={link}
                noRightBar={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/countries/:countryId/knowledge/sightings"
            render={(routeProps) => (
              <EntityStixSightingRelationships
                entityId={country.id}
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

CountryKnowledgeComponent.propTypes = {
  country: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const CountryKnowledge = createFragmentContainer(CountryKnowledgeComponent, {
  country: graphql`
    fragment CountryKnowledge_country on Country {
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
)(CountryKnowledge);
