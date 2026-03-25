import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import CourseOfActionEditionOverview from './CourseOfActionEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';
import { useEntityTypeDisplayName } from '../../../../utils/hooks/useEntityTypeDisplayName';

const CourseOfActionEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const entityTypeDisplayName = useEntityTypeDisplayName();

  const { handleClose, courseOfAction, open, controlledDial } = props;
  const { editContext } = courseOfAction;

  return (
    <Drawer
      title={t_i18n('', { id: 'Update ...', values: { entity_type: entityTypeDisplayName('Course-Of-Action') } })}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
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
