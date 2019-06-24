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
import CourseOfActionHeader from './CourseOfActionHeader';
import CourseOfActionKnowledgeBar from './CourseOfActionKnowledgeBar';

const styles = () => ({
  container: {
    margin: 0,
  },
  content: {
    paddingRight: 260,
  },
});

const inversedRoles = ['usage'];

class CourseOfActionKnowledgeComponent extends Component {
  render() {
    const { classes, courseOfAction } = this.props;
    const link = `/dashboard/techniques/courses_of_action/${
      courseOfAction.id
    }/threats`;
    return (
      <div className={classes.container}>
        <CourseOfActionHeader courseOfAction={courseOfAction} variant="noalias" />
        <CourseOfActionKnowledgeBar courseOfActionId={courseOfAction.id} />
        <div className={classes.content}>
          <Route
            exact
            path="/dashboard/techniques/courses_of_action/:courseOfActionId/threats/relations/:relationId"
            render={routeProps => (
              <StixRelation
                entityId={courseOfAction.id}
                inversedRoles={inversedRoles}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/courses_of_action/:courseOfActionId/threats/overview"
            render={routeProps => (
              <StixDomainEntityKnowledge
                stixDomainEntityId={courseOfAction.id}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/courses_of_action/:courseOfActionId/threats/intrusion_sets"
            render={routeProps => (
              <EntityStixRelations
                entityId={courseOfAction.id}
                relationType="uses"
                targetEntityTypes={['Intrusion-Set']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/courses_of_action/:courseOfActionId/threats/campaigns"
            render={routeProps => (
              <EntityStixRelations
                entityId={courseOfAction.id}
                relationType="uses"
                targetEntityTypes={['Campaign']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />

          <Route
            exact
            path="/dashboard/techniques/courses_of_action/:courseOfActionId/threats/incidents"
            render={routeProps => (
              <EntityStixRelations
                entityId={courseOfAction.id}
                relationType="uses"
                targetEntityTypes={['Incident']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/courses_of_action/:courseOfActionId/threats/malwares"
            render={routeProps => (
              <EntityStixRelations
                entityId={courseOfAction.id}
                relationType="uses"
                targetEntityTypes={['Malware']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/courses_of_action/:courseOfActionId/knowledge/tools"
            render={routeProps => (
              <EntityStixRelations
                entityId={courseOfAction.id}
                relationType="uses"
                targetEntityTypes={['Tools']}
                entityLink={link}
                {...routeProps}
              />
            )}
          />
        </div>
      </div>
    );
  }
}

CourseOfActionKnowledgeComponent.propTypes = {
  courseOfAction: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const CourseOfActionKnowledge = createFragmentContainer(
  CourseOfActionKnowledgeComponent,
  {
    courseOfAction: graphql`
      fragment CourseOfActionKnowledge_courseOfAction on CourseOfAction {
        id
        ...CourseOfActionHeader_courseOfAction
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(CourseOfActionKnowledge);
