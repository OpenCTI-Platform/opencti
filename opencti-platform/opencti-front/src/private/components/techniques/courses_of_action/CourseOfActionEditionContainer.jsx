import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import CourseOfActionEditionOverview from './CourseOfActionEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';
import CourseOfActionDelete from './CourseOfActionDelete';

const CourseOfActionEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const { handleClose, courseOfAction, open, controlledDial } = props;
  const { editContext } = courseOfAction;

  return (
    <Drawer
      title={t_i18n('Update a course of action')}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
    >
      <>
        <CourseOfActionEditionOverview
          courseOfAction={courseOfAction}
          enableReferences={useIsEnforceReference('Course-Of-Action')}
          context={editContext}
          handleClose={handleClose}
        />
        {!useIsEnforceReference('Course-Of-Action')
          && <CourseOfActionDelete id={courseOfAction.id} />
        }
      </>
    </Drawer>
  );
};

const CourseOfActionEditionFragment = createFragmentContainer(
  CourseOfActionEditionContainer,
  {
    courseOfAction: graphql`
      fragment CourseOfActionEditionContainer_courseOfAction on CourseOfAction {
        id
        ...CourseOfActionEditionOverview_courseOfAction
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default CourseOfActionEditionFragment;
