import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import GroupingEditionOverview from './GroupingEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import GroupingDelete from './GroupingDelete';

const GroupingEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const { handleClose, grouping, open, controlledDial } = props;
  const { editContext } = grouping;

  return (
    <Drawer
      title={t_i18n('Update a grouping')}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
    >
      <>
        <GroupingEditionOverview
          grouping={grouping}
          enableReferences={useIsEnforceReference('Grouping')}
          context={editContext}
          handleClose={handleClose}
        />
        {!useIsEnforceReference('Grouping')
          && <GroupingDelete id={grouping.id} />
        }
      </>
    </Drawer>
  );
};

const GroupingEditionFragment = createFragmentContainer(
  GroupingEditionContainer,
  {
    grouping: graphql`
      fragment GroupingEditionContainer_grouping on Grouping {
        id
        ...GroupingEditionOverview_grouping
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default GroupingEditionFragment;
