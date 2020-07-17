import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixRelations from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixRelation from '../../common/stix_core_relationships/StixRelation';
import CountryPopover from './CountryPopover';
import CountryKnowledgeBar from './CountryKnowledgeBar';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
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
        />
        <CountryKnowledgeBar countryId={country.id} />
        <Route
          exact
          path="/dashboard/entities/countries/:countryId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixRelation
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
              stixDomainObjectType="country"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/countries/:countryId/knowledge/cities"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={country.id}
              relationType="localization"
              targetEntityTypes={['City']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/countries/:countryId/knowledge/organizations"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={country.id}
              relationType="localization"
              targetEntityTypes={['Organization']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/countries/:countryId/knowledge/threats"
          render={(routeProps) => (
            <EntityStixRelations
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
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
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
      alias
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(CountryKnowledge);
