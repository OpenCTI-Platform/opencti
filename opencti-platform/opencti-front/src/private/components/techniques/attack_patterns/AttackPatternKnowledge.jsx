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
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class AttackPatternKnowledgeComponent extends Component {
  render() {
    const { classes, attackPattern } = this.props;
    const link = `/dashboard/techniques/attack_patterns/${attackPattern.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          entityType={'Attack-Pattern'}
          stixDomainObject={attackPattern}
          PopoverComponent={<AttackPatternPopover />}
        />
        <Switch>
          <Route
            exact
            path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={attackPattern.id}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={attackPattern.id}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/overview"
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
            path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={attackPattern.id}
                relationshipTypes={['related-to']}
                stixCoreObjectTypes={[
                  'Theat-Actor-Group',
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
            path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/victimology"
            render={(routeProps) => (
              <StixDomainObjectVictimology
                stixDomainObjectId={attackPattern.id}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/threat_actors"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={attackPattern.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Theat-Actor-Group']}
                entityLink={link}
                isRelationReversed={true}
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
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Intrusion-Set']}
                entityLink={link}
                isRelationReversed={true}
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
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Campaign']}
                entityLink={link}
                isRelationReversed={true}
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
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Incident']}
                entityLink={link}
                isRelationReversed={true}
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
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Malware']}
                entityLink={link}
                isRelationReversed={true}
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
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Tool']}
                entityLink={link}
                isRelationReversed={true}
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
                relationshipTypes={['targets']}
                stixCoreObjectTypes={['Vulnerability']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge/observables"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={attackPattern.id}
                relationshipTypes={['related-to']}
                stixCoreObjectTypes={['Stix-Cyber-Observable']}
                entityLink={link}
                allDirections={true}
                isRelationReversed={true}
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
