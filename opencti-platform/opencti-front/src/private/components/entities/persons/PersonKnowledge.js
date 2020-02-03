import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixRelations from '../../common/stix_relations/EntityStixRelations';
import StixDomainEntityKnowledge from '../../common/stix_domain_entities/StixDomainEntityKnowledge';
import StixRelation from '../../common/stix_relations/StixRelation';
import PersonPopover from './PersonPopover';
import PersonKnowledgeBar from './PersonKnowledgeBar';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
});

class PersonKnowledgeComponent extends Component {
  render() {
    const { classes, person } = this.props;
    const link = `/dashboard/entities/persons/${person.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainEntityHeader
          stixDomainEntity={person}
          PopoverComponent={<PersonPopover />}
        />
        <PersonKnowledgeBar personId={person.id} />
        <Route
          exact
          path="/dashboard/entities/persons/:personId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixRelation
              entityId={person.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/persons/:personId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainEntityKnowledge
              stixDomainEntityId={person.id}
              stixDomainEntityType="person"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/persons/:personId/knowledge/organizations"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={person.id}
              relationType="gathering"
              targetEntityTypes={['Organization']}
              entityLink={link}
              creationIsFrom={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/persons/:personId/knowledge/locations"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={person.id}
              relationType="localization"
              targetEntityTypes={['City', 'Country', 'Region']}
              entityLink={link}
              creationIsFrom={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/persons/:personId/knowledge/threats"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={person.id}
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
        <Route
          exact
          path="/dashboard/entities/persons/:organizationId/knowledge/attribution"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={person.id}
              relationType="attributed-to"
              targetEntityTypes={[
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

PersonKnowledgeComponent.propTypes = {
  person: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const PersonKnowledge = createFragmentContainer(PersonKnowledgeComponent, {
  person: graphql`
    fragment PersonKnowledge_person on User {
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
)(PersonKnowledge);
