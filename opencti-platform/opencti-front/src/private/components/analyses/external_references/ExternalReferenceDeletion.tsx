import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import { deleteNodeFromId } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../components/DeleteDialog';

export const externalReferenceDeletionDeleteMutation = graphql`
  mutation ExternalReferenceDeletionDeleteMutation($id: ID!) {
    externalReferenceEdit(id: $id) {
      delete
    }
  }
`;

interface ExternalReferenceDeletionProps {
  id: string;
  isOpen: boolean
  handleClose: () => void;
  objectId?: string;
  handleRemove?: (() => void) | undefined;
  isExternalReferenceAttachment?: boolean;
}

const ExternalReferenceDeletion: FunctionComponent<
ExternalReferenceDeletionProps
> = ({ id, objectId, isOpen, handleClose, handleRemove, isExternalReferenceAttachment }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_External-Reference') },
  });
  const [commit] = useApiMutation(
    externalReferenceDeletionDeleteMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );
  const deletion = useDeletion({});
  const { setDeleting, handleCloseDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      updater: (store) => {
        if (handleRemove && objectId) {
          deleteNodeFromId(
            store,
            objectId,
            'Pagination_externalReferences',
            undefined,
            id,
          );
        }
      },
      onCompleted: () => {
        setDeleting(false);
        if (handleRemove) {
          handleCloseDelete();
        } else {
          navigate('/dashboard/analyses/external_references');
        }
      },
    });
  };
  return (
    <DeleteDialog
      deletion={deletion}
      submitDelete={submitDelete}
      isOpen={isOpen}
      onClose={handleClose}
      message={t_i18n('Do you want to delete this external reference?')}
      warning={isExternalReferenceAttachment
        ? { message: t_i18n('This external reference is linked to a file. If you delete it, the file will be deleted as well.') }
        : undefined}
    />
  );
};

export default ExternalReferenceDeletion;
