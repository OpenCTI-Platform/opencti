import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixDomainObjectThreatKnowledge from '../../common/stix_domain_objects/StixDomainObjectThreatKnowledge';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import XOpenctiIncidentPopover from './XOpenctiXOpenctiIncidentPopover';
import XOpenctiIncidentKnowledgeBar from './XOpenctiXOpenctiIncidentKnowledgeBar';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectKillChain from '../../common/stix_domain_objects/StixDomainObjectKillChain';
import StixDomainObjectVictimology from '../../common/stix_domain_objects/StixDomainObjectVictimology';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
});

class XOpenctiIncidentKnowledgeComponent extends Component {
  render() {
    const { classes, xOpenctiIncident } = this.props;
    const link = `/dashboard/threats/xOpenctiIncidents/${xOpenctiIncident.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={xOpenctiIncident}
          PopoverComponent={<XOpenctiIncidentPopover />}
        />
        <XOpenctiIncidentKnowledgeBar
          xOpenctiIncidentId={xOpenctiIncident.id}
        />
        <Route
          exact
          path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship
              entityId={xOpenctiIncident.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainObjectThreatKnowledge
              stixDomainObjectId={xOpenctiIncident.id}
              stixDomainObjectType="xOpenctiIncident"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId/knowledge/attribution"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={xOpenctiIncident.id}
              relationType="attributed-to"
              targetEntityTypes={[
                'Threat-Actor',
                'Intrusion-Set',
                'Campaign',
                'Organization',
                'User',
              ]}
              entityLink={link}
              creationIsFrom={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId/knowledge/malwares"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={xOpenctiIncident.id}
              relationType="uses"
              targetEntityTypes={['Malware']}
              entityLink={link}
              creationIsFrom={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId/knowledge/victimology"
          render={(routeProps) => (
            <StixDomainObjectVictimology
              stixDomainObjectId={xOpenctiIncident.id}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId/knowledge/ttp"
          render={(routeProps) => (
            <StixDomainObjectKillChain
              stixDomainObjectId={xOpenctiIncident.id}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId/knowledge/tools"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={xOpenctiIncident.id}
              relationType="uses"
              targetEntityTypes={['Tool']}
              entityLink={link}
              creationIsFrom={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/xOpenctiIncidents/:xOpenctiIncidentId/knowledge/vulnerabilities"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={xOpenctiIncident.id}
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

XOpenctiIncidentKnowledgeComponent.propTypes = {
  xOpenctiIncident: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const XOpenctiXOpenctiIncidentKnowledge = createFragmentContainer(
  XOpenctiIncidentKnowledgeComponent,
  {
    xOpenctiIncident: graphql`
      fragment XOpenctiIncidentKnowledge_xOpenctiIncident on XOpenctiIncident {
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
)(XOpenctiXOpenctiIncidentKnowledge);
