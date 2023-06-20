import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import NarrativePopover from './NarrativePopover';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class NarrativeKnowledgeComponent extends Component {
  render() {
    const { classes, narrative } = this.props;
    const link = `/dashboard/techniques/narratives/${narrative.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          entityType={'Narrative'}
          disableSharing={true}
          stixDomainObject={narrative}
          PopoverComponent={<NarrativePopover />}
        />
        <Switch>
          <Route
            exact
            path="/dashboard/techniques/narratives/:narrativeId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={narrative.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/narratives/:narrativeId/knowledge/sightings/:sightingId"
            render={(routeProps) => (
              <StixSightingRelationship
                entityId={narrative.id}
                paddingRight={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/narratives/:narrativeId/knowledge/overview"
            render={(routeProps) => (
              <StixDomainObjectThreatKnowledge
                stixDomainObjectId={narrative.id}
                stixDomainObjectType="Narrative"
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/narratives/:narrativeId/knowledge/related"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
                relationshipTypes={['related-to']}
                stixCoreObjectTypes={[
                  'Threat-Actor',
                  'Intrusion-Set',
                  'Campaign',
                  'Incident',
                  'Malware',
                  'Narrative',
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
            path="/dashboard/techniques/narratives/:narrativeId/knowledge/threat_actors"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Threat-Actor']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/narratives/:narrativeId/knowledge/intrusion_sets"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
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
            path="/dashboard/techniques/narratives/:narrativeId/knowledge/campaigns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
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
            path="/dashboard/techniques/narratives/:narrativeId/knowledge/attack_patterns"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Attack-Pattern']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/narratives/:narrativeId/knowledge/malwares"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
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
            path="/dashboard/techniques/narratives/:narrativeId/knowledge/channels"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Channel']}
                entityLink={link}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/narratives/:narrativeId/knowledge/vulnerabilities"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Vulnerability']}
                entityLink={link}
                isRelationReversed={false}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/narratives/:narrativeId/knowledge/incidents"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
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
            path="/dashboard/techniques/narratives/:narrativeId/knowledge/observables"
            render={(routeProps) => (
              <EntityStixCoreRelationships
                entityId={narrative.id}
                relationshipTypes={['related-to']}
                stixCoreObjectTypes={['Stix-Cyber-Observable']}
                entityLink={link}
                allDirections={true}
                isRelationReversed={true}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/narratives/:narrativeId/knowledge/sightings"
            render={(routeProps) => (
              <EntityStixSightingRelationships
                entityId={narrative.id}
                entityLink={link}
                noRightBar={true}
                stixCoreObjectTypes={[
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

NarrativeKnowledgeComponent.propTypes = {
  narrative: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const NarrativeKnowledge = createFragmentContainer(
  NarrativeKnowledgeComponent,
  {
    narrative: graphql`
      fragment NarrativeKnowledge_narrative on Narrative {
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
)(NarrativeKnowledge);
