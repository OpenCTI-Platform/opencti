import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixRelations from '../../common/stix_relations/EntityStixRelations';
import StixDomainEntityKnowledge from '../../common/stix_domain_entities/StixDomainEntityKnowledge';
import StixRelation from '../../common/stix_relations/StixRelation';
import OrganizationPopover from './OrganizationPopover';
import OrganizationKnowledgeBar from './OrganizationKnowledgeBar';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
});

const inversedRoles = ['target'];

class OrganizationKnowledgeComponent extends Component {
  render() {
    const { classes, organization } = this.props;
    const link = `/dashboard/entities/organizations/${organization.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainEntityHeader
          stixDomainEntity={organization}
          PopoverComponent={<OrganizationPopover />}
        />
        <OrganizationKnowledgeBar organizationId={organization.id} />
        <Route
          exact
          path="/dashboard/entities/organizations/:organizationId/knowledge/relations/:relationId"
          render={routeProps => (
            <StixRelation
              entityId={organization.id}
              inversedRoles={inversedRoles}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/organizations/:organizationId/knowledge/overview"
          render={routeProps => (
            <StixDomainEntityKnowledge
              stixDomainEntityId={organization.id}
              stixDomainEntityType="organization"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/organizations/:organizationId/knowledge/sectors"
          render={routeProps => (
            <EntityStixRelations
              entityId={organization.id}
              relationType="gathering"
              targetEntityTypes={['Sector']}
              entityLink={link}
              creationIsFrom={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/organizations/:organizationId/knowledge/locations"
          render={routeProps => (
            <EntityStixRelations
              entityId={organization.id}
              relationType="localization"
              targetEntityTypes={['Region', 'Country', 'City']}
              entityLink={link}
              creationIsFrom={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/organizations/:organizationId/knowledge/persons"
          render={routeProps => (
            <EntityStixRelations
              entityId={organization.id}
              relationType="gathering"
              targetEntityTypes={['User']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/organizations/:organizationId/knowledge/threats"
          render={routeProps => (
            <EntityStixRelations
              entityId={organization.id}
              resolveRelationType="targets"
              resolveRelationRole="target"
              resolveViaTypes={[
                {
                  entityType: 'Intrusion-Set',
                  relationType: 'attributed-to',
                  relationRole: 'attribution',
                },
                {
                  entityType: 'Campaign',
                  relationType: 'attributed-to',
                  relationRole: 'attribution',
                },
                {
                  entityType: 'Incident',
                  relationType: 'attributed-to',
                  relationRole: 'attribution',
                },
                {
                  entityType: 'Malware',
                  relationType: 'attributed-to',
                  relationRole: 'attribution',
                },
              ]}
              relationType="targets"
              targetEntityTypes={[
                'Country',
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'Incident',
                'Malware',
              ]}
              entityLink={link}
              creationIsFrom={false}
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
        alias
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(OrganizationKnowledge);
