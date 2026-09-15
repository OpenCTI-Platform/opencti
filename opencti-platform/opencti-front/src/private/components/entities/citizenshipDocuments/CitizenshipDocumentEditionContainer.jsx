import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import CitizenshipDocumentEditionOverview from './CitizenshipDocumentEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';

const CitizenshipDocumentEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const { handleClose, citizenshipDocument, open, controlledDial } = props;
  const { editContext } = citizenshipDocument;

  return (
    <Drawer
      title={t_i18n('Update a citizenship document')}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
    >
      <CitizenshipDocumentEditionOverview
        citizenshipDocument={citizenshipDocument}
        enableReferences={useIsEnforceReference('Citizenship-Document')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

const CitizenshipDocumentEditionFragment = createFragmentContainer(
  CitizenshipDocumentEditionContainer,
  {
    citizenshipDocument: graphql`
      fragment CitizenshipDocumentEditionContainer_citizenshipDocument on CitizenshipDocument {
        id
        ...CitizenshipDocumentEditionOverview_citizenshipDocument
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default CitizenshipDocumentEditionFragment;
