import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import EntityStixRelations from '../stix_relation/EntityStixRelations';
import StixDomainEntityKnowledge from '../stix_domain_entity/StixDomainEntityKnowledge';
import StixRelation from '../stix_relation/StixRelation';
import OrganizationHeader from './OrganizationHeader';
import OrganizationKnowledgeBar from './OrganizationKnowledgeBar';

const styles = () => ({
  container: {
    margin: 0,
  },
  content: {
    paddingRight: 260,
  },
});

const inversedRelations = [
  'user',
  'threat-actor',
  'intrusion-set',
  'campaign',
  'incident',
  'malware',
];

class OrganizationKnowledgeComponent extends Component {
  render() {
    const { classes, organization, location } = this.props;
    const link = `/dashboard/catalogs/organizations/${
      organization.id
    }/knowledge`;
    return (
      <div className={classes.container}>
        <OrganizationHeader organization={organization} variant="noalias" />
        <OrganizationKnowledgeBar organizationId={organization.id} />
        <div className={classes.content}>
          <Route
            exact
            path="/dashboard/catalogs/organizations/:organizationId/knowledge/relations/:relationId"
            render={routeProps => (
              <StixRelation
                entityId={organization.id}
                inversedRelations={inversedRelations}
                {...routeProps}
              />
            )}
          />

          {location.pathname.includes('overview') ? (
            <StixDomainEntityKnowledge stixDomainEntityId={organization.id} />
          ) : (
            ''
          )}

          {location.pathname.includes('sectors') ? (
            <EntityStixRelations
              entityId={organization.id}
              relationType="gathering"
              targetEntityTypes={['Sector']}
              entityLink={link}
            />
          ) : (
            ''
          )}

          {location.pathname.includes('persons') ? (
            <EntityStixRelations
              entityId={organization.id}
              relationType="gathering"
              targetEntityTypes={['User']}
              entityLink={link}
            />
          ) : (
            ''
          )}

          {location.pathname.includes('threats') ? (
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
            />
          ) : (
            ''
          )}

          {location.pathname.includes('attribution') ? (
            <EntityStixRelations
              entityId={organization.id}
              relationType="attributed-to"
              targetEntityTypes={[
                'Identity',
                'Intrusion-Set',
                'Campaign',
                'Incident',
                'Malware',
              ]}
              entityLink={link}
            />
          ) : (
            ''
          )}

          {location.pathname.includes('entities') ? (
            <EntityStixRelations
              entityId={organization.id}
              relationType="related-to"
              targetEntityTypes={['Identity']}
              entityLink={link}
            />
          ) : (
            ''
          )}
        </div>
      </div>
    );
  }
}

OrganizationKnowledgeComponent.propTypes = {
  organization: PropTypes.object,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

const OrganizationKnowledge = createFragmentContainer(
  OrganizationKnowledgeComponent,
  {
    organization: graphql`
      fragment OrganizationKnowledge_organization on Organization {
        id
        ...OrganizationHeader_organization
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(OrganizationKnowledge);
