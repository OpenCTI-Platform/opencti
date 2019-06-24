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
import CountryHeader from './CountryHeader';
import CountryKnowledgeBar from './CountryKnowledgeBar';

const styles = () => ({
  container: {
    margin: 0,
  },
  content: {
    paddingRight: 260,
  },
});

const inversedRoles = ['location', 'target'];

class CountryKnowledgeComponent extends Component {
  render() {
    const { classes, country } = this.props;
    const link = `/dashboard/entities/countries/${country.id}/knowledge`;
    return (
      <div className={classes.container}>
        <CountryHeader country={country} variant="noalias" />
        <CountryKnowledgeBar countryId={country.id} />
        <div className={classes.content}>
          <Route
            exact
            path="/dashboard/entities/countries/:countryId/knowledge/relations/:relationId"
            render={routeProps => (
              <StixRelation
                entityId={country.id}
                inversedRoles={inversedRoles}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/countries/:countryId/knowledge/overview"
            render={routeProps => (
              <StixDomainEntityKnowledge
                stixDomainEntityId={country.id}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/countries/:countryId/knowledge/cities"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="localization"
                resolveRelationRole="location"
                entityId={country.id}
                relationType="localization"
                targetEntityTypes={['City']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/countries/:countryId/knowledge/organizations"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="localization"
                resolveRelationRole="location"
                entityId={country.id}
                relationType="localization"
                targetEntityTypes={['Organization']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/countries/:countryId/knowledge/threats"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="localization"
                resolveRelationRole="location"
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
                entityId={country.id}
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
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/entities/countries/:countryId/knowledge/entities"
            render={routeProps => (
              <EntityStixRelations
                entityId={country.id}
                relationType="related-to"
                targetEntityTypes={['Identity']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
        </div>
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
      ...CountryHeader_country
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(CountryKnowledge);
