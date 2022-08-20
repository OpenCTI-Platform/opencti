import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import CourseOfActionPopover from './CourseOfActionPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class CourseOfActionKnowledgeComponent extends Component {
  render() {
    const { classes, courseOfAction, enableReferences } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={courseOfAction}
          PopoverComponent={<CourseOfActionPopover />}
          enableReferences={enableReferences}
          isOpenctiAlias={true}
        />
        <Switch>
          <Route
            exact
            path="/dashboard/arsenal/courses_of_action/:courseOfActionId/knowledge/relations/:relationId"
            render={(routeProps) => (
              <StixCoreRelationship
                entityId={courseOfAction.id}
                {...routeProps}
              />
            )}
          />
        </Switch>
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
        name
        x_opencti_aliases
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(CourseOfActionKnowledge);
