import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import OrganizationPopover from './OrganizationPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import StixCoreObjectStixCyberObservables from '../../observations/stix_cyber_observables/StixCoreObjectStixCyberObservables';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class OrganizationKnowledgeComponent extends Component {
  render() {
    const { classes, organization } = this.props;
    const link = `/dashboard/entities/organizations/${organization.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={organization}
          PopoverComponent={<OrganizationPopover />}
        />
        <StixCoreObjectKnowledgeBar
          stixCoreObjectLink={link}
          availableSections={[
            'organizations',
            'individuals',
            'threat_actors',
            'intrusion_sets',
            'campaigns',
            'incidents',
            'malwares',
            'observables',
            'sightings',
          ]}
        />
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
          path="/dashboard/entities/organizations/:organizationId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainObjectKnowledge
              stixDomainObjectId={organization.id}
              stixDomainObjectType="Organization"
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
              relationshipType="part-of"
              role="part-of_to"
              targetStixDomainObjectTypes={['Organization']}
              entityLink={link}
              isRelationReversed={true}
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
              relationshipType="part-of"
              targetStixDomainObjectTypes={['Individual']}
              entityLink={link}
              isRelationReversed={true}
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
              relationshipType="targets"
              targetStixDomainObjectTypes={['Threat-Actor']}
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
              relationshipType="targets"
              targetStixDomainObjectTypes={['Intrusion-Set']}
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
              relationshipType="targets"
              targetStixDomainObjectTypes={['Campaign']}
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
              relationshipType="targets"
              targetStixDomainObjectTypes={['X-OpenCTI-Incident']}
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
              relationshipType="targets"
              targetStixDomainObjectTypes={['Malware']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/organizations/:organizationId/knowledge/observables"
          render={(routeProps) => (
            <StixCoreObjectStixCyberObservables
              stixCoreObjectId={organization.id}
              stixCoreObjectLink={link}
              noRightBar={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/organizations/:organizationId/knowledge/sightings"
          render={(routeProps) => (
            <EntityStixSightingRelationships
              entityId={organization.id}
              entityLink={link}
              noRightBar={true}
              isTo={true}
              {...routeProps}
            />
          )}
        />
      </div>
    );
  }
}

OrganizationKnowledgeComponent.propTypes = {
  organization: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
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
