import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import CourseOfActionEditionOverview from './CourseOfActionEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const CourseOfActionEditionContainer = (props) => {
  const { t } = useFormatter();

  const { handleClose, courseOfAction, open } = props;
  const { editContext } = courseOfAction;

  return (
    <Drawer
      title={t('Update a course of action')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
    >
      <CourseOfActionEditionOverview
        courseOfAction={courseOfAction}
        enableReferences={useIsEnforceReference('Course-Of-Action')}
        context={editContext}
        handleClose={handleClose}
      />
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
