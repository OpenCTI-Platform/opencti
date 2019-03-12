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

const inversedRelations = [
  'organization',
  'intrusion-set',
  'campaign',
  'incident',
  'malware',
  'threat-actor',
];

class CountryKnowledgeComponent extends Component {
  render() {
    const { classes, country, location } = this.props;
    const link = `/dashboard/catalogs/countries/${country.id}/knowledge`;
    return (
      <div className={classes.container}>
        <CountryHeader country={country} variant='noalias'/>
        <CountryKnowledgeBar countryId={country.id}/>
        <div className={classes.content}>
          <Route exact path='/dashboard/catalogs/countries/:countryId/knowledge/relations/:relationId' render={
            routeProps => <StixRelation
              entityId={country.id}
              inversedRelations={inversedRelations}
              {...routeProps}
              />
          }/>

          {location.pathname.includes('overview') ? <StixDomainEntityKnowledge
            stixDomainEntityId={country.id}
          /> : ''}

          {location.pathname.includes('organizations') ? <EntityStixRelations
            resolveRelationType='localization'
            resolveRelationRole='location'
            entityId={country.id}
            relationType='localization'
            targetEntityTypes={['Organization']}
            entityLink={link}
          /> : ''}

          {location.pathname.includes('threats') ? <EntityStixRelations
            resolveRelationType='localization'
            resolveRelationRole='location'
            resolveViaTypes={[
              { entityType: 'Intrusion-Set', relationType: 'attributed-to', relationRole: 'attribution' },
              { entityType: 'Campaign', relationType: 'attributed-to', relationRole: 'attribution' },
              { entityType: 'Incident', relationType: 'attributed-to', relationRole: 'attribution' },
              { entityType: 'Malware', relationType: 'attributed-to', relationRole: 'attribution' },
            ]}
            entityId={country.id}
            relationType='targets'
            targetEntityTypes={['Country', 'Threat-Actor', 'Intrusion-Set', 'Campaign', 'Incident', 'Malware']}
            entityLink={link}
          /> : ''}

          {location.pathname.includes('attribution') ? <EntityStixRelations
            resolveRelationType='attributed-to'
            resolveRelationRole='origin'
            entityId={country.id}
            relationType='attributed-to'
            targetEntityTypes={['Identity']}
            entityLink={link}
          /> : ''}

          {location.pathname.includes('entities') ? <EntityStixRelations
            entityId={country.id}
            relationType='related-to'
            targetEntityTypes={['Identity']}
            entityLink={link}
          /> : ''}
        </div>
      </div>
    );
  }
}

CountryKnowledgeComponent.propTypes = {
  country: PropTypes.object,
  classes: PropTypes.object,
  location: PropTypes.object,
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
