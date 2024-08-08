import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import GroupingEditionOverview from './GroupingEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import useHelper from '../../../../utils/hooks/useHelper';
import { SchemaAttributesQuery } from '../../../../utils/hooks/useSchemaAttributes';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

const GroupingEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const { handleClose, grouping, open, controlledDial } = props;
  const { editContext } = grouping;

  const queryRef = useQueryLoading(SchemaAttributesQuery, {
    entityType: 'Grouping',
  });

  return (
    <Drawer
      title={t_i18n('Update a grouping')}
      open={open}
      onClose={handleClose}
      variant={!isFABReplaced && open == null ? DrawerVariant.update : undefined}
      context={editContext}
      controlledDial={isFABReplaced ? controlledDial : undefined}
    >
      <GroupingEditionOverview
        grouping={grouping}
        queryReference={queryRef}
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
