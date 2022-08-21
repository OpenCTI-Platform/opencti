import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import AttackPatternPopover from './AttackPatternPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import StixCoreObjectStixCyberObservables
  from '../../observations/stix_cyber_observables/StixCoreObjectStixCyberObservables';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class AttackPatternKnowledgeComponent extends Component {
  render() {
    const { classes, attackPattern, enableReferences } = this.props;
    const link = `/dashboard/arsenal/attack_patterns/${attackPattern.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={attackPattern}
          PopoverComponent={<AttackPatternPopover />}
          enableReferences={enableReferences}
        />
        <Switch>
          <Route
            exact
            path="/dashboard/arsenal/attack_patterns/:attackPatternId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={attackPattern.id}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/attack_patterns/:attackPatternId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={attackPattern.id}
                {...routeProps}
              />
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
            path="/dashboard/arsenal/attack_patterns/:attackPatternId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={attackPattern.id}
                relationshipTypes={['related-to']}
                targetStixDomainObjectTypes={[
                  'Threat-Actor',
                  'Intrusion-Set',
                  'Campaign',
                  'Incident',
                  'Malware',
                  'Tool',
                  'Vulnerability',
                  'Individual',
                  'Organization',
                  'Sector',
                  'Region',
                  'Country',
                  'City',
                  'Position',
                ]}
                entityLink={link}
                allDirections={true}
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
                relationshipTypes={['uses']}
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
                relationshipTypes={['uses']}
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
                relationshipTypes={['uses']}
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
                relationshipTypes={['uses']}
                targetStixDomainObjectTypes={['Incident']}
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
                relationshipTypes={['uses']}
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
                relationshipTypes={['uses']}
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
                relationshipTypes={['targets']}
                targetStixDomainObjectTypes={['Vulnerability']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/attack_patterns/:attackPatternId/knowledge/observables"
            render={(routeProps) => (
              <StixCoreObjectStixCyberObservables
                stixCoreObjectId={attackPattern.id}
                stixCoreObjectLink={link}
                noRightBar={true}
                {...routeProps}
              />
            )}
          />
        </Switch>
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
