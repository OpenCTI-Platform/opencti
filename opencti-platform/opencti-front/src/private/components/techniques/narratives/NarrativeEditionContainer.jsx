import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import NarrativeEditionOverview from './NarrativeEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const NarrativeEditionContainer = (props) => {
  const { t } = useFormatter();

  const { handleClose, narrative, open } = props;
  const { editContext } = narrative;

  return (
    <Drawer
      title={t('Update a narrative')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
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
