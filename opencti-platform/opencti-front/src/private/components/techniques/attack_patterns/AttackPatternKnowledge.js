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
import AttackPatternPopover from './AttackPatternPopover';
import AttackPatternKnowledgeBar from './AttackPatternKnowledgeBar';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
});

class AttackPatternKnowledgeComponent extends Component {
  render() {
    const { classes, attackPattern } = this.props;
    const link = `/dashboard/techniques/attack_patterns/${attackPattern.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainEntityHeader
          stixDomainEntity={attackPattern}
          PopoverComponent={<AttackPatternPopover />}
        />
        <AttackPatternKnowledgeBar attackPatternId={attackPattern.id} />
        <Route
          exact
          path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixRelation entityId={attackPattern.id} {...routeProps} />
          )}
        />
        <Route
          exact
          path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainEntityKnowledge
              stixDomainEntityId={attackPattern.id}
              stixDomainEntityType="attack-pattern"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/intrusion_sets"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={attackPattern.id}
              relationType="uses"
              targetEntityTypes={['Intrusion-Set']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/campaigns"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={attackPattern.id}
              relationType="uses"
              targetEntityTypes={['Campaign']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />

        <Route
          exact
          path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/incidents"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={attackPattern.id}
              relationType="uses"
              targetEntityTypes={['Incident']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/malwares"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={attackPattern.id}
              relationType="uses"
              targetEntityTypes={['Malware']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/tools"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={attackPattern.id}
              relationType="uses"
              targetEntityTypes={['Tool']}
              entityLink={link}
              creationIsFrom={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/vulnerabilities"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={attackPattern.id}
              relationType="targets"
              targetEntityTypes={['Vulnerability']}
              entityLink={link}
              creationIsFrom={true}
              {...routeProps}
            />
          )}
        />
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
)(AttackPatternKnowledge);
