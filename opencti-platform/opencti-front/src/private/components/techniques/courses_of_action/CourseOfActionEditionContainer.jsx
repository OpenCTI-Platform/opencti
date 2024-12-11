import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import CourseOfActionEditionOverview from './CourseOfActionEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import useHelper from '../../../../utils/hooks/useHelper';

const CourseOfActionEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const { handleClose, courseOfAction, open, controlledDial } = props;
  const { editContext } = courseOfAction;

  return (
    <Drawer
      title={t_i18n('Update a course of action')}
      open={open}
      onClose={handleClose}
      variant={!isFABReplaced && open == null ? DrawerVariant.update : undefined}
      context={editContext}
      controlledDial={isFABReplaced ? controlledDial : undefined}
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
