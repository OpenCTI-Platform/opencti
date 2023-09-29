import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import GroupingEditionOverview from './GroupingEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

const GroupingEditionContainer = (props) => {
  const { t } = useFormatter();

  const { handleClose, grouping, open } = props;
  const { editContext } = grouping;

  return (
    <Drawer
      title={t('Update a grouping')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
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
