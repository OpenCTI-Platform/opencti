import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes } from 'react-router-dom';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import EntityStixCoreRelationshipsIndicators from '../../common/stix_core_relationships/views/indicators/EntityStixCoreRelationshipsIndicators';
import EntityStixCoreRelationshipsStixCyberObservable from '../../common/stix_core_relationships/views/stix_cyber_observable/EntityStixCoreRelationshipsStixCyberObservable';
import withRouter from '../../../../utils/compat-router/withRouter';

class ToolKnowledgeComponent extends Component {
  render() {
    const { tool } = this.props;
    const link = `/dashboard/arsenal/tools/${tool.id}/knowledge`;
    return (
      <>
        <Routes>
          <Route
            path="/relations/:relationId/*"
            element={
              <StixCoreRelationship
                entityId={tool.id}
                paddingRight={true}
              />
            }
          />
          <Route
            path="/sightings/:sightingId/*"
            element={
              <StixSightingRelationship
                entityId={tool.id}
                paddingRight={true}
              />
            }
          />
          <Route
            path="/overview"
            element={
              <StixDomainObjectThreatKnowledge
                stixDomainObjectId={tool.id}
                stixDomainObjectName={tool.name}
                stixDomainObjectType="Tool"
              />
            }
          />
          <Route
            path="/related"
            element={
              <EntityStixCoreRelationships
                entityId={tool.id}
                relationshipTypes={['related-to']}
                entityLink={link}
                allDirections={true}
              />
            }
          />
          <Route
            path="/threats"
            element={
              <EntityStixCoreRelationships
                entityId={tool.id}
                relationshipTypes={['uses']}
                isRelationReversed={true}
                entityLink={link}
                stixCoreObjectTypes={[
                  'Threat-Actor',
                  'Intrusion-Set',
                  'Campaign',
                  'Incident',
                  'Malware',
                  'Channel',
                ]}
              />
                }
          />
          <Route
            path="/threat_actors"
            element={
              <EntityStixCoreRelationships
                entityId={tool.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Threat-Actor']}
                entityLink={link}
                isRelationReversed={true}
              />
            }
          />
          <Route
            path="/intrusion_sets"
            element={
              <EntityStixCoreRelationships
                entityId={tool.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Intrusion-Set']}
                entityLink={link}
                isRelationReversed={true}
              />
            }
          />
          <Route
            path="/campaigns"
            element={
              <EntityStixCoreRelationships
                entityId={tool.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Campaign']}
                entityLink={link}
                isRelationReversed={true}
              />
            }
          />
          <Route
            path="/attack_patterns"
            element={
              <EntityStixCoreRelationships
                entityId={tool.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Attack-Pattern']}
                entityLink={link}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/malwares"
            element={
              <EntityStixCoreRelationships
                entityId={tool.id}
                relationshipTypes={['delivers', 'drops']}
                stixCoreObjectTypes={['Malware']}
                entityLink={link}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/vulnerabilities"
            element={
              <EntityStixCoreRelationships
                entityId={tool.id}
                relationshipTypes={['uses', 'has', 'targets']}
                stixCoreObjectTypes={['Vulnerability']}
                entityLink={link}
                isRelationReversed={false}
              />
            }
          />
          <Route
            path="/incidents"
            element={
              <EntityStixCoreRelationships
                entityId={tool.id}
                relationshipTypes={['uses']}
                stixCoreObjectTypes={['Incident']}
                entityLink={link}
                isRelationReversed={true}
              />
            }
          />
          <Route
            path="/indicators"
            element={
              <EntityStixCoreRelationshipsIndicators
                entityId={tool.id}
                entityLink={link}
                defaultStartTime={tool.first_seen}
                defaultStopTime={tool.last_seen}
              />
            }
          />
          <Route
            path="/observables"
            element={
              <EntityStixCoreRelationshipsStixCyberObservable
                entityId={tool.id}
                entityLink={link}
                defaultStartTime={tool.first_seen}
                defaultStopTime={tool.last_seen}
                isRelationReversed={true}
                relationshipTypes={['related-to']}
              />
            }
          />
          <Route
            path="/sightings"
            element={
              <EntityStixSightingRelationships
                entityId={tool.id}
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
              />
            }
          />
        </Routes>
      </>
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

export default R.compose(inject18n, withRouter)(ToolKnowledge);
