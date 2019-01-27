import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import EntityStixRelations from '../stix_relation/EntityStixRelations';
import StixDomainEntityKnowledge from '../stix_domain_entity/StixDomainEntityKnowledge';
import StixRelation from '../stix_relation/StixRelation';
import IncidentHeader from './IncidentHeader';
import IncidentKnowledgeBar from './IncidentKnowledgeBar';

const styles = () => ({
  container: {
    margin: 0,
  },
  content: {
    paddingRight: 260,
  },
});

const inversedRelations = ['incident', 'incident', 'intrusion-set'];

class IncidentKnowledgeComponent extends Component {
  render() {
    const { classes, incident, location } = this.props;
    const link = `/dashboard/knowledge/incidents/${incident.id}/knowledge`;
    return (
      <div className={classes.container}>
        <IncidentHeader incident={incident} variant='noalias'/>
        <IncidentKnowledgeBar incidentId={incident.id}/>
        <div className={classes.content}>
          <Route exact path='/dashboard/knowledge/incidents/:incidentId/knowledge/relations/:relationId' render={
            routeProps => <StixRelation entityId={incident.id} {...routeProps} inversedRelations={inversedRelations}/>
          }/>
          {location.pathname.includes('overview') ? <StixDomainEntityKnowledge stixDomainEntityId={incident.id}/> : ''}
          {location.pathname.includes('attribution') ? <EntityStixRelations entityId={incident.id} relationType='uses' targetEntityType='Intrusion-Set' entityLink={link}/> : ''}
          {location.pathname.includes('incidents') ? <EntityStixRelations entityId={incident.id} relationType='uses' targetEntityType='Incident' entityLink={link}/> : ''}
          {location.pathname.includes('incidents') ? <EntityStixRelations entityId={incident.id} relationType='uses' targetEntityType='Incident' entityLink={link}/> : ''}
          {location.pathname.includes('victimology') ? <EntityStixRelations entityId={incident.id} relationType='targets' targetEntityType='Identity' entityLink={link}/> : ''}
          {location.pathname.includes('ttp') ? <EntityStixRelations entityId={incident.id} relationType='uses' targetEntityType='Attack-Pattern' entityLink={link}/> : ''}
          {location.pathname.includes('tools') ? <EntityStixRelations entityId={incident.id} relationType='uses' targetEntityType='Tool' entityLink={link}/> : ''}
          {location.pathname.includes('vulnerabilities') ? <EntityStixRelations entityId={incident.id} relationType='targets' targetEntityType='Vulnerability' entityLink={link}/> : ''}
        </div>
      </div>
    );
  }
}

IncidentKnowledgeComponent.propTypes = {
  incident: PropTypes.object,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

const IncidentKnowledge = createFragmentContainer(IncidentKnowledgeComponent, {
  incident: graphql`
      fragment IncidentKnowledge_incident on Incident {
          id
          ...IncidentHeader_incident
      }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(IncidentKnowledge);
