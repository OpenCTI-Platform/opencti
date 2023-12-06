import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import { Button } from '@mui/material';
import { Create } from '@mui/icons-material';
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
    const { t, courseOfActionId } = this.props;
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
                controlledDial={({ onOpen }) => (
                  <Button
                    style={{
                      marginLeft: '3px',
                      fontSize: 'small',
                    }}
                    variant='outlined'
                    onClick={onOpen}
                  >
                    {t('Edit')} <Create />
                  </Button>
                )}
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
