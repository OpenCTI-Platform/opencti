import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import NarrativeEditionOverview from './NarrativeEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';
import NarrativeDelete from './NarrativeDelete';

const NarrativeEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const { handleClose, narrative, open, controlledDial } = props;
  const { editContext } = narrative;

  return (
    <Drawer
      title={t_i18n('Update a narrative')}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
    >
      <>
        <NarrativeEditionOverview
          narrative={narrative}
          enableReferences={useIsEnforceReference('Narrative')}
          context={editContext}
          handleClose={handleClose}
        />
        {!useIsEnforceReference('Narrative')
          && <NarrativeDelete id={narrative.id} />
        }
      </>
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
