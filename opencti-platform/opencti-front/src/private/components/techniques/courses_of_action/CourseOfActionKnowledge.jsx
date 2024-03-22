import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';

class CourseOfActionKnowledgeComponent extends Component {
  render() {
    const { courseOfAction } = this.props;
    return (
      <>
        <Switch>
          <Route
            exact
            path="/dashboard/techniques/courses_of_action/:courseOfActionId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={courseOfAction.id}
                {...routeProps}
              />
            )}
          />
        </Switch>
      </>
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
        name
        x_opencti_aliases
      }
    `,
  },
);

export default withRouter(CourseOfActionKnowledge);
