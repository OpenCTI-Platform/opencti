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
import AttackPatternHeader from './AttackPatternHeader';
import AttackPatternKnowledgeBar from './AttackPatternKnowledgeBar';

const styles = () => ({
  container: {
    margin: 0,
  },
  content: {
    paddingRight: 260,
  },
});

const inversedRoles = ['usage'];

class AttackPatternKnowledgeComponent extends Component {
  render() {
    const { classes, attackPattern } = this.props;
    const link = `/dashboard/techniques/attack_patterns/${
      attackPattern.id
    }/threats`;
    return (
      <div className={classes.container}>
        <AttackPatternHeader attackPattern={attackPattern} variant="noalias" />
        <AttackPatternKnowledgeBar attackPatternId={attackPattern.id} />
        <div className={classes.content}>
          <Route
            exact
            path="/dashboard/techniques/attack_patterns/:attackPatternId/threats/relations/:relationId"
            render={routeProps => (
              <StixRelation
                entityId={attackPattern.id}
                inversedRoles={inversedRoles}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/attack_patterns/:attackPatternId/threats/overview"
            render={routeProps => (
              <StixDomainEntityKnowledge
                stixDomainEntityId={attackPattern.id}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/attack_patterns/:attackPatternId/threats/intrusion_sets"
            render={routeProps => (
              <EntityStixRelations
                entityId={attackPattern.id}
                relationType="uses"
                targetEntityTypes={['Intrusion-Set']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/attack_patterns/:attackPatternId/threats/campaigns"
            render={routeProps => (
              <EntityStixRelations
                entityId={attackPattern.id}
                relationType="uses"
                targetEntityTypes={['Campaign']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />

          <Route
            exact
            path="/dashboard/techniques/attack_patterns/:attackPatternId/threats/incidents"
            render={routeProps => (
              <EntityStixRelations
                entityId={attackPattern.id}
                relationType="uses"
                targetEntityTypes={['Incident']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/attack_patterns/:attackPatternId/threats/malwares"
            render={routeProps => (
              <EntityStixRelations
                entityId={attackPattern.id}
                relationType="uses"
                targetEntityTypes={['Malware']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/tools"
            render={routeProps => (
              <EntityStixRelations
                entityId={attackPattern.id}
                relationType="uses"
                targetEntityTypes={['Tools']}
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

AttackPatternKnowledgeComponent.propTypes = {
  attackPattern: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const AttackPatternKnowledge = createFragmentContainer(
  AttackPatternKnowledgeComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternKnowledge_attackPattern on AttackPattern {
        id
        ...AttackPatternHeader_attackPattern
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(AttackPatternKnowledge);
