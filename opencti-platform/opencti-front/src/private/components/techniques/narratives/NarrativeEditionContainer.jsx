import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import NarrativeEditionOverview from './NarrativeEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import useHelper from '../../../../utils/hooks/useHelper';

const NarrativeEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const { handleClose, narrative, open, controlledDial } = props;
  const { editContext } = narrative;

  return (
    <Drawer
      title={t_i18n('Update a narrative')}
      open={open}
      onClose={handleClose}
      variant={!isFABReplaced && open == null ? DrawerVariant.update : undefined}
      context={editContext}
      controlledDial={isFABReplaced ? controlledDial : undefined}
    >
      <NarrativeEditionOverview
        narrative={narrative}
        enableReferences={useIsEnforceReference('Narrative')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

const NarrativeEditionFragment = createFragmentContainer(
  NarrativeEditionContainer,
  {
    narrative: graphql`
      fragment NarrativeEditionContainer_narrative on Narrative {
        id
        ...NarrativeEditionOverview_narrative
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default NarrativeEditionFragment;
