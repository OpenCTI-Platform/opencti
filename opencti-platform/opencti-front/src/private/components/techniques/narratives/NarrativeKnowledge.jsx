import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { createFragmentContainer, graphql } from 'react-relay';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import EntityStixCoreRelationshipsStixCyberObservable from '../../common/stix_core_relationships/views/stix_cyber_observable/EntityStixCoreRelationshipsStixCyberObservable';

class NarrativeKnowledgeComponent extends Component {
  render() {
    const { narrative } = this.props;
    const link = `/dashboard/techniques/narratives/${narrative.id}/knowledge`;
    return (
      <>
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
              <EntityStixCoreRelationshipsStixCyberObservable
                {...routeProps}
                entityId={narrative.id}
                entityLink={link}
                defaultStartTime={narrative.first_seen}
                defaultStopTime={narrative.last_seen}
                isRelationReversed={true}
                relationshipTypes={['related-to']}
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
      </>
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

export default withRouter(NarrativeKnowledge);
