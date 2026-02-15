import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import React, { ReactNode, UIEvent } from 'react';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../components/i18n';
import useDeletion from '../../../../utils/hooks/useDeletion';
import stopEvent from '../../../../utils/domEvent';
import DeleteDialog from '../../../../components/DeleteDialog';
import { deleteNode } from '../../../../utils/store';
import { SSODefinitionDeletionMutation } from '@components/settings/sso_definitions/__generated__/SSODefinitionDeletionMutation.graphql';

const ssoDefinitionDeletionMutation = graphql`
    mutation SSODefinitionDeletionMutation($id: ID!) {
        singleSignOnDelete(id: $id)
    }
`;

interface ChildrenProps {
  handleOpenDelete: (e?: UIEvent) => void;
  deleting: boolean;
}

interface SSODefinitionDeletionProps {
  ssoId: string;
  paginationOptions?: Record<string, unknown>;
  onDeleteComplete?: () => void;
  children: (props: ChildrenProps) => ReactNode;
}

const SSODefinitionDeletion = ({ ssoId, paginationOptions, onDeleteComplete, children }: SSODefinitionDeletionProps) => {
  const { t_i18n } = useFormatter();

  const [deleteMutation, deleting] = useApiMutation<SSODefinitionDeletionMutation>(
    ssoDefinitionDeletionMutation,
    undefined,
    { successMessage: `${t_i18n('entity_SSO')} ${t_i18n('successfully deleted')}` },
  );

  const deletion = useDeletion({});
  const { handleOpenDelete, handleCloseDelete } = deletion;

  const onDelete = (e: UIEvent) => {
    stopEvent(e);
    deleteMutation({
      variables: { id: ssoId },
      updater: (store: RecordSourceSelectorProxy) => {
        if (paginationOptions) {
          deleteNode(store, 'Pagination_singleSignOns', paginationOptions, ssoId);
        }
      },
      onCompleted: () => {
        handleCloseDelete();
        onDeleteComplete?.();
      },
      onError: () => {
        handleCloseDelete();
      },
    });
  };

  return (
    <>
      {children({ handleOpenDelete, deleting })}
      <DeleteDialog
        deletion={deletion}
        submitDelete={onDelete}
        message={t_i18n('Do you want to delete this Authentication?')}
      />
    </>
  );
};

export default SSODefinitionDeletion;
