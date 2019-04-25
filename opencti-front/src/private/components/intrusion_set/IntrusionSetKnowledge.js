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
import IntrusionSetHeader from './IntrusionSetHeader';
import IntrusionSetKnowledgeBar from './IntrusionSetKnowledgeBar';

const styles = () => ({
  container: {
    margin: 0,
  },
  content: {
    paddingRight: 260,
  },
});

const inversedRoles = ['origin'];

class IntrusionSetKnowledgeComponent extends Component {
  render() {
    const { classes, intrusionSet } = this.props;
    const link = `/dashboard/knowledge/intrusion_sets/${
      intrusionSet.id
    }/knowledge`;
    return (
      <div className={classes.container}>
        <IntrusionSetHeader intrusionSet={intrusionSet} variant="noalias" />
        <IntrusionSetKnowledgeBar intrusionSetId={intrusionSet.id} />
        <div className={classes.content}>
          <Route
            exact
            path="/dashboard/knowledge/intrusion_sets/:intrusionSetId/knowledge/relations/:relationId"
            render={routeProps => (
              <StixRelation
                entityId={intrusionSet.id}
                inversedRoles={inversedRoles}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/knowledge/intrusion_sets/:intrusionSetId/knowledge/overview"
            render={routeProps => (
              <StixDomainEntityKnowledge
                stixDomainEntityId={intrusionSet.id}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/knowledge/intrusion_sets/:intrusionSetId/knowledge/attribution"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="attributed-to"
                resolveRelationRole="origin"
                entityId={intrusionSet.id}
                relationType="attributed-to"
                targetEntityTypes={['Identity']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/knowledge/intrusion_sets/:intrusionSetId/knowledge/campaigns"
            render={routeProps => (
              <EntityStixRelations
                entityId={intrusionSet.id}
                relationType="attributed-to"
                targetEntityTypes={['Campaign']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/knowledge/intrusion_sets/:intrusionSetId/knowledge/incidents"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="attributed-to"
                resolveRelationRole="origin"
                entityId={intrusionSet.id}
                relationType="attributed-to"
                targetEntityTypes={['Incident']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/knowledge/intrusion_sets/:intrusionSetId/knowledge/malwares"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="attributed-to"
                resolveRelationRole="origin"
                entityId={intrusionSet.id}
                relationType="uses"
                targetEntityTypes={['Malware']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/knowledge/intrusion_sets/:intrusionSetId/knowledge/victimology"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="attributed-to"
                resolveRelationRole="origin"
                resolveViaTypes={[
                  {
                    entityType: 'Organization',
                    relationType: 'gathering',
                    relationRole: 'part_of',
                  },
                  {
                    entityType: 'Organization',
                    relationType: 'localization',
                    relationRole: 'localized',
                  },
                  {
                    entityType: 'Country',
                    relationType: 'localization',
                    relationRole: 'localized',
                  },
                ]}
                entityId={intrusionSet.id}
                relationType="targets"
                targetEntityTypes={[
                  'Organization',
                  'Sector',
                  'Country',
                  'Region',
                ]}
                entityLink={link}
                exploreLink={`/dashboard/explore/victimology/${
                  intrusionSet.id
                }`}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/knowledge/intrusion_sets/:intrusionSetId/knowledge/ttp"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="attributed-to"
                resolveRelationRole="origin"
                entityId={intrusionSet.id}
                relationType="uses"
                targetEntityTypes={['Attack-Pattern']}
                entityLink={link}
                exploreLink={`/dashboard/explore/attack_patterns/${intrusionSet.id}`}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/knowledge/intrusion_sets/:intrusionSetId/knowledge/tools"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="attributed-to"
                resolveRelationRole="origin"
                entityId={intrusionSet.id}
                relationType="uses"
                targetEntityTypes={['Tool']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/knowledge/intrusion_sets/:intrusionSetId/knowledge/vulnerabilities"
            render={routeProps => (
              <EntityStixRelations
                resolveRelationType="attributed-to"
                resolveRelationRole="origin"
                entityId={intrusionSet.id}
                relationType="targets"
                targetEntityTypes={['Vulnerability']}
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

IntrusionSetKnowledgeComponent.propTypes = {
  intrusionSet: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const IntrusionSetKnowledge = createFragmentContainer(
  IntrusionSetKnowledgeComponent,
  {
    intrusionSet: graphql`
      fragment IntrusionSetKnowledge_intrusionSet on IntrusionSet {
        id
        ...IntrusionSetHeader_intrusionSet
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(IntrusionSetKnowledge);
