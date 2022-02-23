import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import ToolPopover from './ToolPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixCoreObjectStixCyberObservables from '../../observations/stix_cyber_observables/StixCoreObjectStixCyberObservables';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class ToolKnowledgeComponent extends Component {
  render() {
    const { classes, tool } = this.props;
    const link = `/dashboard/arsenal/tools/${tool.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={tool}
          PopoverComponent={<ToolPopover />}
        />
        <Switch>
          <Route
            exact
            path="/dashboard/arsenal/tools/:toolId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={tool.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/tools/:toolId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={tool.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/tools/:toolId/knowledge/overview"
            render={(routeProps) => (
              <StixDomainObjectThreatKnowledge
                stixDomainObjectId={tool.id}
                stixDomainObjectType="Tool"
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/tools/:toolId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={tool.id}
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
            path="/dashboard/arsenal/tools/:toolId/knowledge/threat_actors"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={tool.id}
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
            path="/dashboard/arsenal/tools/:toolId/knowledge/intrusion_sets"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={tool.id}
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
            path="/dashboard/arsenal/tools/:toolId/knowledge/campaigns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={tool.id}
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
            path="/dashboard/arsenal/tools/:toolId/knowledge/attack_patterns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={tool.id}
                relationshipTypes={['uses']}
                targetStixDomainObjectTypes={['Attack-Pattern']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/tools/:toolId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={tool.id}
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
            path="/dashboard/arsenal/tools/:toolId/knowledge/vulnerabilities"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={tool.id}
                relationshipTypes={['uses']}
                targetStixDomainObjectTypes={['Vulnerability']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/tools/:toolId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={tool.id}
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
            path="/dashboard/arsenal/tools/:toolId/knowledge/observables"
            render={(routeProps) => (
              <StixCoreObjectStixCyberObservables
                stixCoreObjectId={tool.id}
                stixCoreObjectLink={link}
                noRightBar={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/arsenal/tools/:toolId/knowledge/sightings"
            render={(routeProps) => (
              <EntityStixSightingRelationships
                entityId={tool.id}
                entityLink={link}
                noRightBar={true}
                targetStixDomainObjectTypes={[
                  'Region',
                  'Country',
                  'City',
                  'Position',
                  'Sector',
                  'Organization',
                  'Individual',
                  'System',
                ]}
                {...routeProps}
              />
            )}
          />
        </Switch>
      </div>
    );
  }
}

ToolKnowledgeComponent.propTypes = {
  tool: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ToolKnowledge = createFragmentContainer(ToolKnowledgeComponent, {
  tool: graphql`
    fragment ToolKnowledge_tool on Tool {
      id
      name
      aliases
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(ToolKnowledge);
