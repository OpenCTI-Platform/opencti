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
import ThreatActorHeader from './ThreatActorHeader';
import ThreatActorKnowledgeBar from './ThreatActorKnowledgeBar';

const styles = () => ({
  container: {
    margin: 0,
  },
  content: {
    paddingRight: 260,
  },
});

const inversedRelations = ['intrusion-set', 'campaign', 'incident'];

class ThreatActorKnowledgeComponent extends Component {
  render() {
    const { classes, threatActor, location } = this.props;
    const link = `/dashboard/knowledge/threat_actors/${threatActor.id}/knowledge`;
    return (
      <div className={classes.container}>
        <ThreatActorHeader threatActor={threatActor} variant='noalias'/>
        <ThreatActorKnowledgeBar threatActorId={threatActor.id}/>
        <div className={classes.content}>
          <Route exact path='/dashboard/knowledge/threat_actors/:threatActorId/knowledge/relations/:relationId' render={
            routeProps => <StixRelation entityId={threatActor.id} {...routeProps} inversedRelations={inversedRelations}/>
          }/>
          {location.pathname.includes('overview') ? <StixDomainEntityKnowledge stixDomainEntityId={threatActor.id}/> : ''}
          {location.pathname.includes('intrusion_sets') ? <EntityStixRelations entityId={threatActor.id} relationType='attributed-to' targetEntityTypes={['Intrusion-Set']} entityLink={link}/> : ''}
          {location.pathname.includes('campaigns') ? <EntityStixRelations resolveRelationType='attributed-to' entityId={threatActor.id} relationType='attributed-to' targetEntityTypes={['Campaign']} entityLink={link}/> : ''}
          {location.pathname.includes('incidents') ? <EntityStixRelations resolveRelationType='attributed-to' entityId={threatActor.id} relationType='attributed-to' targetEntityTypes={['Incident']} entityLink={link}/> : ''}
          {location.pathname.includes('victimology') ? <EntityStixRelations resolveRelationType='attributed-to' entityId={threatActor.id} relationType='targets' targetEntityTypes={['Identity']} entityLink={link}/> : ''}
          {location.pathname.includes('malwares') ? <EntityStixRelations resolveRelationType='attributed-to' entityId={threatActor.id} relationType='uses' targetEntityTypes={['Malware']} entityLink={link}/> : ''}
          {location.pathname.includes('ttp') ? <EntityStixRelations resolveRelationType='attributed-to' entityId={threatActor.id} relationType='uses' targetEntityTypes={['Attack-Pattern']} entityLink={link}/> : ''}
          {location.pathname.includes('tools') ? <EntityStixRelations resolveRelationType='attributed-to' entityId={threatActor.id} relationType='uses' targetEntityTypes={['Tool']} entityLink={link}/> : ''}
          {location.pathname.includes('vulnerabilities') ? <EntityStixRelations resolveRelationType='attributed-to' entityId={threatActor.id} relationType='targets' targetEntityTypes={['Vulnerability']} entityLink={link}/> : ''}
        </div>
      </div>
    );
  }
}

ThreatActorKnowledgeComponent.propTypes = {
  threatActor: PropTypes.object,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

const ThreatActorKnowledge = createFragmentContainer(ThreatActorKnowledgeComponent, {
  threatActor: graphql`
      fragment ThreatActorKnowledge_threatActor on ThreatActor {
          id
          ...ThreatActorHeader_threatActor
      }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(ThreatActorKnowledge);
