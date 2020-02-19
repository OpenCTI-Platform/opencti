import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixRelations from '../../common/stix_relations/EntityStixRelations';
import StixDomainEntityThreatKnowledge from '../../common/stix_domain_entities/StixDomainEntityThreatKnowledge';
import StixRelation from '../../common/stix_relations/StixRelation';
import IncidentPopover from './IncidentPopover';
import IncidentKnowledgeBar from './IncidentKnowledgeBar';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';
import StixDomainEntityKillChain from '../../common/stix_domain_entities/StixDomainEntityKillChain';
import StixDomainEntityVictimology from "../../common/stix_domain_entities/StixDomainEntityVictimology";

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
});

class IncidentKnowledgeComponent extends Component {
  render() {
    const { classes, incident } = this.props;
    const link = `/dashboard/threats/incidents/${incident.id}/knowledge`;
    return (
      <div className={classes.container}>
        <StixDomainEntityHeader
          stixDomainEntity={incident}
          PopoverComponent={<IncidentPopover />}
        />
        <IncidentKnowledgeBar incidentId={incident.id} />
        <Route
          exact
          path="/dashboard/threats/incidents/:incidentId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixRelation
              entityId={incident.id}
              paddingRight={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/incidents/:incidentId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainEntityThreatKnowledge
              stixDomainEntityId={incident.id}
              stixDomainEntityType="incident"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/incidents/:incidentId/knowledge/attribution"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={incident.id}
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
          path="/dashboard/threats/incidents/:incidentId/knowledge/malwares"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={incident.id}
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
          path="/dashboard/threats/incidents/:incidentId/knowledge/victimology"
          render={(routeProps) => (
            <StixDomainEntityVictimology
              stixDomainEntityId={incident.id}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/incidents/:incidentId/knowledge/ttp"
          render={(routeProps) => (
            <StixDomainEntityKillChain
              stixDomainEntityId={incident.id}
              entityLink={link}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/incidents/:incidentId/knowledge/tools"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={incident.id}
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
          path="/dashboard/threats/incidents/:incidentId/knowledge/vulnerabilities"
          render={(routeProps) => (
            <EntityStixRelations
              entityId={incident.id}
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

IncidentKnowledgeComponent.propTypes = {
  incident: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const IncidentKnowledge = createFragmentContainer(IncidentKnowledgeComponent, {
  incident: graphql`
    fragment IncidentKnowledge_incident on Incident {
      id
      name
      alias
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(IncidentKnowledge);
