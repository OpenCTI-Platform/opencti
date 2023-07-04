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
import OrganizationPopover from './OrganizationPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectAuthorKnowledge from '../../common/stix_domain_objects/StixDomainObjectAuthorKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const styles = () => ({
  container: {
    margin: 0,
    padding: 0,
  },
});

class OrganizationKnowledgeComponent extends Component {
  render() {
    const { classes, organization, viewAs, onViewAs } = this.props;
    const link = `/dashboard/entities/organizations/${organization.id}/knowledge`;
    return (
      <div
        className={classes.container}
        style={{ paddingRight: viewAs === 'knowledge' ? 200 : 0 }}
      >
        <StixDomainObjectHeader
          entityType={'Organization'}
          disableSharing={true}
          stixDomainObject={organization}
          PopoverComponent={<OrganizationPopover />}
          onViewAs={onViewAs.bind(this)}
          viewAs={viewAs}
        />
        <Switch>
          <Route
            exact
            path="/dashboard/entities/organizations/:organizationId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={organization.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/organizations/:organizationId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={organization.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/organizations/:organizationId/knowledge/overview"
            render={(routeProps) => (viewAs === 'knowledge' ? (
                <StixDomainObjectKnowledge
                  stixDomainObjectId={organization.id}
                  stixDomainObjectType="Organization"
                  {...routeProps}
                />
            ) : (
                <StixDomainObjectAuthorKnowledge
                  stixDomainObjectId={organization.id}
                  stixDomainObjectType="Organization"
                  {...routeProps}
                />
            ))
            }
          />
          <Route
            exact
            path="/dashboard/entities/organizations/:organizationId/knowledge/threats"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={organization.id}
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
            path="/dashboard/entities/organizations/:organizationId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={organization.id}
                relationshipTypes={['related-to']}
                entityLink={link}
                allDirections={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/organizations/:organizationId/knowledge/organizations"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={organization.id}
                relationshipTypes={['part-of']}
                role="part-of_to"
                stixCoreObjectTypes={['Organization']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/organizations/:organizationId/knowledge/individuals"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={organization.id}
                relationshipTypes={['part-of']}
                stixCoreObjectTypes={['Individual']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/organizations/:organizationId/knowledge/locations"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={organization.id}
                relationshipTypes={['located-at']}
                stixCoreObjectTypes={['Location']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/organizations/:organizationId/knowledge/sectors"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={organization.id}
                relationshipTypes={['part-of']}
                stixCoreObjectTypes={['Sector']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/organizations/:organizationId/knowledge/used_tools"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={organization.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Tool']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/organizations/:organizationId/knowledge/threat_actors"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={organization.id}
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
            path="/dashboard/entities/organizations/:organizationId/knowledge/intrusion_sets"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={organization.id}
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
            path="/dashboard/entities/organizations/:organizationId/knowledge/campaigns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={organization.id}
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
            path="/dashboard/entities/organizations/:organizationId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={organization.id}
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
            path="/dashboard/entities/organizations/:organizationId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={organization.id}
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
            path="/dashboard/entities/organizations/:organizationId/knowledge/attack_patterns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={organization.id}
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
            path="/dashboard/entities/organizations/:organizationId/knowledge/tools"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={organization.id}
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
            path="/dashboard/entities/organizations/:organizationId/knowledge/vulnerabilities"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={organization.id}
                relationshipTypes={['related-to']}
                stixCoreObjectTypes={['Vulnerability']}
                entityLink={link}
                allDirections={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/organizations/:organizationId/knowledge/observables"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={organization.id}
                relationshipTypes={['related-to']}
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
  }
}

OrganizationKnowledgeComponent.propTypes = {
  organization: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  viewAs: PropTypes.string,
  onViewAs: PropTypes.func,
};

const OrganizationKnowledge = createFragmentContainer(
  OrganizationKnowledgeComponent,
  {
    organization: graphql`
      fragment OrganizationKnowledge_organization on Organization {
        id
        name
        x_opencti_aliases
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(OrganizationKnowledge);
