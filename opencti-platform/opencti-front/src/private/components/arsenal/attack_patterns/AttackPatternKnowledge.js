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
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class AttackPatternKnowledgeComponent extends Component {
  render() {
    const { classes, attackPattern } = this.props;
    const link = `/dashboard/arsenal/attack_patterns/${attackPattern.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={attackPattern}
          PopoverComponent={<AttackPatternPopover />}
        />
        <StixCoreObjectKnowledgeBar
          stixCoreObjectLink={link}
          availableSections={[
            'threat_actors',
            'intrusion_sets',
            'campaigns',
            'incidents',
            'tools',
            'vulnerabilities',
            'malwares',
            'sightings',
          ]}
        />
        <Route
          exact
          path="/dashboard/arsenal/attack_patterns/:attackPatternId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship entityId={attackPattern.id} {...routeProps} />
          )}
        />
        <Route
          exact
          path="/dashboard/arsenal/attack_patterns/:attackPatternId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainObjectKnowledge
              stixDomainObjectId={attackPattern.id}
              stixDomainObjectType="Attack-Pattern"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/arsenal/attack_patterns/:attackPatternId/knowledge/threat_actors"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={attackPattern.id}
              relationshipType="uses"
              targetStixDomainObjectTypes={['Threat-Actor']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/arsenal/attack_patterns/:attackPatternId/knowledge/intrusion_sets"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={attackPattern.id}
              relationshipType="uses"
              targetStixDomainObjectTypes={['Intrusion-Set']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/arsenal/attack_patterns/:attackPatternId/knowledge/campaigns"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={attackPattern.id}
              relationshipType="uses"
              targetStixDomainObjectTypes={['Campaign']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />

        <Route
          exact
          path="/dashboard/arsenal/attack_patterns/:attackPatternId/knowledge/incidents"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={attackPattern.id}
              relationshipType="uses"
              targetStixDomainObjectTypes={['XOpenCTIIncident']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/arsenal/attack_patterns/:attackPatternId/knowledge/malwares"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={attackPattern.id}
              relationshipType="uses"
              targetStixDomainObjectTypes={['Malware']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/arsenal/attack_patterns/:attackPatternId/knowledge/tools"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={attackPattern.id}
              relationshipType="uses"
              targetStixDomainObjectTypes={['Tool']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/arsenal/attack_patterns/:attackPatternId/knowledge/vulnerabilities"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={attackPattern.id}
              relationshipType="targets"
              targetStixDomainObjectTypes={['Vulnerability']}
              entityLink={link}
              isRelationReversed={false}
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
