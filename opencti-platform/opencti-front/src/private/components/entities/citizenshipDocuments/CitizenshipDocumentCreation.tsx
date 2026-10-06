import { CitizenshipDocumentsPaginationQuery$variables } from '@components/entities/__generated__/CitizenshipDocumentsPaginationQuery.graphql';
import React, { FunctionComponent, useState } from 'react';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import CitizenshipDocumentCreationForm from '@components/entities/citizenshipDocuments/CitizenshipDocumentCreationForm';
import { useFormatter } from '../../../../components/i18n';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { insertNode } from '../../../../utils/store';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';

export const citizenshipDocumentCreationMutation = graphql`
mutation CitizenshipDocumentCreationMutation($input: CitizenshipDocumentAddInput!) {
    citizenshipDocumentAdd(input: $input) {
    id
        ...CitizenshipDocument_citizenshipDocument
    }
}
`;

interface CitizenshipDocumentCreationProps {
  paginationOptions: CitizenshipDocumentsPaginationQuery$variables;
}

const CitizenshipDocumentCreation: FunctionComponent<CitizenshipDocumentCreationProps> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [bulkOpen, setBulkOpen] = useState(false);

  const updater = (store: RecordSourceSelectorProxy) => {
    insertNode(
      store,
      'Pagination_citizenshipDocuments',
      paginationOptions,
      'citizenshipDocumentAdd',
    );
  };

  const CreateCitizenshipDocumentControlledDial = (
    props: DrawerControlledDialProps,
  ) => (
    <CreateEntityControlledDial entityType="Citizenship-Document" {...props} />
  );

  return (
    <Drawer
      title={t_i18n('Create a citizenship document')}
      header={<BulkTextModalButton onClick={() => setBulkOpen(true)} />}
      controlledDial={CreateCitizenshipDocumentControlledDial}
    >
      {({ onClose }) => (
        <CitizenshipDocumentCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
        />
      )}
    </Drawer>
  );
};

export default CitizenshipDocumentCreation;
