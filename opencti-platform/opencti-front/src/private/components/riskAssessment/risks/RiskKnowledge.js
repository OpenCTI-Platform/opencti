import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import RiskPopover from './RiskPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';
import StixCoreObjectStixCyberObservables from '../../observations/stix_cyber_observables/StixCoreObjectStixCyberObservables';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

class RiskKnowledgeComponent extends Component {
  render() {
    const { classes, risk } = this.props;
    const link = `/activities/risk_assessment/risks/${risk.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={risk}
          PopoverComponent={<RiskPopover />}
        />
        <Route
          exact
          path="/activities/risk_assessment/risks/:riskId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship
              entityId={risk.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/activities/risk_assessment/risks/:riskId/knowledge/sightings/:sightingId"
          render={(routeProps) => (
            <StixSightingRelationship
              entityId={risk.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/activities/risk_assessment/risks/:riskId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainObjectThreatKnowledge
              stixDomainObjectId={risk.id}
              stixDomainObjectType="Risk"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/activities/risk_assessment/risks/:riskId/knowledge/related"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={risk.id}
              relationshipTypes={['related-to', 'part-of']}
              targetStixDomainObjectTypes={[
                'Risk',
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
          path="/activities/risk_assessment/risks/:riskId/knowledge/victimology"
          render={(routeProps) => (
            <StixDomainObjectVictimology
              stixDomainObjectId={risk.id}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/activities/risk_assessment/risks/:riskId/knowledge/risks"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={risk.id}
              relationshipTypes={['part-of']}
              targetStixDomainObjectTypes={['Risk']}
              entityLink={link}
              allDirections={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/activities/risk_assessment/risks/:riskId/knowledge/network"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={risk.id}
              relationshipTypes={['attributed-to']}
              targetStixDomainObjectTypes={['Intrusion-Set']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/activities/risk_assessment/risks/:riskId/knowledge/software"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={risk.id}
              relationshipTypes={['attributed-to']}
              targetStixDomainObjectTypes={['Software']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/activities/risk_assessment/risks/:riskId/knowledge/attack_patterns"
          render={(routeProps) => (
            <StixDomainObjectAttackPatterns
              stixDomainObjectId={risk.id}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/activities/risk_assessment/risks/:riskId/knowledge/malwares"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={risk.id}
              relationshipTypes={['uses']}
              targetStixDomainObjectTypes={['Malware']}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/activities/risk_assessment/risks/:riskId/knowledge/tools"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={risk.id}
              relationshipTypes={['uses']}
              targetStixDomainObjectTypes={['Tool']}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/activities/risk_assessment/risks/:riskId/knowledge/vulnerabilities"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={risk.id}
              relationshipTypes={['targets']}
              targetStixDomainObjectTypes={['Vulnerability']}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/activities/risk_assessment/risks/:riskId/knowledge/incidents"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={risk.id}
              relationshipTypes={['attributed-to']}
              targetStixDomainObjectTypes={['Incident']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/activities/risk_assessment/risks/:riskId/knowledge/observables"
          render={(routeProps) => (
            <StixCoreObjectStixCyberObservables
              cyioCoreObjectId={risk.id}
              stixCoreObjectLink={link}
              noRightBar={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/activities/risk_assessment/risks/:riskId/knowledge/infrastructures"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={risk.id}
              relationshipTypes={['uses', 'compromises']}
              targetStixDomainObjectTypes={['Infrastructure']}
              entityLink={link}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/activities/risk_assessment/risks/:riskId/knowledge/sightings"
          render={(routeProps) => (
            <EntityStixSightingRelationships
              entityId={risk.id}
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
      </div>
    );
  }
}

RiskKnowledgeComponent.propTypes = {
  risk: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const RiskKnowledge = createFragmentContainer(
  RiskKnowledgeComponent,
  {
    risk: graphql`
      fragment RiskKnowledge_risk on ThreatActor {
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
)(RiskKnowledge);
