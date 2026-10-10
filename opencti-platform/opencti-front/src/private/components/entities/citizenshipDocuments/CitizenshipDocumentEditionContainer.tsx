import React, { FunctionComponent } from 'react';
import Drawer, { DrawerControlledDialType } from '@components/common/drawer/Drawer';
import { createFragmentContainer, graphql } from 'react-relay';
import {
  CitizenshipDocumentEditionContainer_citizenshipDocument$data,
} from '@components/entities/citizenshipDocuments/__generated__/CitizenshipDocumentEditionContainer_citizenshipDocument.graphql';
import CitizenshipDocumentEditionOverview from '@components/entities/citizenshipDocuments/CitizenshipDocumentEditionOverview';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

interface citizenshipDocumentContainerProps {
  handleClose: () => void;
  citizenshipDocument: CitizenshipDocumentEditionContainer_citizenshipDocument$data;
  controlledDial?: DrawerControlledDialType;
}

const CitizenshipDocumentEditionContainer: FunctionComponent<citizenshipDocumentContainerProps> = ({
  handleClose,
  citizenshipDocument,
  controlledDial,
}) => {
  const { t_i18n } = useFormatter();
  const { editContext } = citizenshipDocument;

  return (
    <Drawer
      title={t_i18n('Update a citizenship document')}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
    >
      <CitizenshipDocumentEditionOverview
        citizenshipDocument={citizenshipDocument}
        enableReferences={useIsEnforceReference('CitizenshipDocument')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

export default createFragmentContainer(
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
