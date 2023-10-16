import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import CourseOfActionEditionContainer from './CourseOfActionEditionContainer';
import { courseOfActionEditionOverviewFocus } from './CourseOfActionEditionOverview';
import Loader from '../../../../components/Loader';

export const courseOfActionEditionQuery = graphql`
  query CourseOfActionEditionContainerQuery($id: String!) {
    courseOfAction(id: $id) {
      ...CourseOfActionEditionContainer_courseOfAction
    }
  }
`;

class CourseOfActionEdition extends Component {
  handleClose() {
    commitMutation({
      mutation: courseOfActionEditionOverviewFocus,
      variables: {
        id: this.props.courseOfActionId,
        input: { focusOn: '' },
      },
    });
  }

  render() {
    const { courseOfActionId } = this.props;
    return (
      <QueryRenderer
        query={courseOfActionEditionQuery}
        variables={{ id: courseOfActionId }}
        render={({ props }) => {
          if (props) {
            return (
              <CourseOfActionEditionContainer
                courseOfAction={props.courseOfAction}
                handleClose={this.handleClose.bind(this)}
              />
            );
          }
          return <Loader variant="inElement" />;
        }}
      />
    );
  }
}

CourseOfActionEdition.propTypes = {
  courseOfActionId: PropTypes.string,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
)(CourseOfActionEdition);
