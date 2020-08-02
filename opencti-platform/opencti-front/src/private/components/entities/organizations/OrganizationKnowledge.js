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
import OrganizationKnowledgeBar from './OrganizationKnowledgeBar';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
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
        <OrganizationKnowledgeBar organizationId={organization.id} />
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
          path="/dashboard/entities/organizations/:organizationId/knowledge/sectors"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipType="part-of"
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
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipType="localization"
              targetEntityTypes={['Region', 'Country', 'City']}
              entityLink={link}
              creationIsFrom={true}
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
              role="gather"
              relationshipType="part-of"
              targetEntityTypes={['Organization']}
              entityLink={link}
              creationIsFrom={false}
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
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipType="targets"
              targetEntityTypes={[
                'Country',
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'XOpenCTIIncident',
                'Malware',
              ]}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/organizations/:organizationId/knowledge/attribution"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={organization.id}
              relationshipType="attributed-to"
              targetEntityTypes={[
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'XOpenCTIIncident',
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
        aliases
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(OrganizationKnowledge);
