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
import AttackPatternPopover from './AttackPatternPopover';
import AttackPatternKnowledgeBar from './AttackPatternKnowledgeBar';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';

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
        <StixDomainObjectHeader
          stixDomainObject={attackPattern}
          PopoverComponent={<AttackPatternPopover />}
        />
        <AttackPatternKnowledgeBar attackPatternId={attackPattern.id} />
        <Route
          exact
          path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship entityId={attackPattern.id} {...routeProps} />
          )}
        />
        <Route
          exact
          path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainObjectKnowledge
              stixDomainObjectId={attackPattern.id}
              stixDomainObjectType="attack-pattern"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/intrusion_sets"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={attackPattern.id}
              relationship_type="uses"
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
            <EntityStixCoreRelationships
              entityId={attackPattern.id}
              relationship_type="uses"
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
            <EntityStixCoreRelationships
              entityId={attackPattern.id}
              relationship_type="uses"
              targetEntityTypes={['XOpenctiIncident']}
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
            <EntityStixCoreRelationships
              entityId={attackPattern.id}
              relationship_type="uses"
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
            <EntityStixCoreRelationships
              entityId={attackPattern.id}
              relationship_type="uses"
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
            <EntityStixCoreRelationships
              entityId={attackPattern.id}
              relationship_type="targets"
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
        aliases
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(AttackPatternKnowledge);
