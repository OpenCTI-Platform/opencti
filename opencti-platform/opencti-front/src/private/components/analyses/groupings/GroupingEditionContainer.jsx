import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import GroupingEditionOverview from './GroupingEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import useHelper from '../../../../utils/hooks/useHelper';

const GroupingEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const FABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const { handleClose, grouping, open, controlledDial } = props;
  const { editContext } = grouping;

  return (
    <Drawer
      title={t_i18n('Update a grouping')}
      open={open}
      onClose={handleClose}
      variant={!FABReplaced && open == null ? DrawerVariant.update : undefined}
      context={editContext}
      controlledDial={FABReplaced ? controlledDial : undefined}
    >
      <GroupingEditionOverview
        grouping={grouping}
        enableReferences={useIsEnforceReference('Grouping')}
        context={editContext}
        handleClose={handleClose}
      />
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
