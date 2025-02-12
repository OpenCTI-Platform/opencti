import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import Button from '@mui/material/Button';
import { useNavigate } from 'react-router-dom';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
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
  objectId?: string;
  handleRemove: (() => void) | undefined;
  isExternalReferenceAttachment?: boolean;
}

const ExternalReferenceDeletion: FunctionComponent<
ExternalReferenceDeletionProps
> = ({ id, objectId, handleRemove, isExternalReferenceAttachment }) => {
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
  const { setDeleting, handleOpenDelete, handleCloseDelete, deleting } = deletion;
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
    <>
      <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
        <Button
          color="error"
          variant="contained"
          onClick={handleOpenDelete}
          disabled={deleting}
          sx={{ marginTop: 2 }}
        >
          {t_i18n('Delete')}
        </Button>
      </Security>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={isExternalReferenceAttachment ? t_i18n(
          'This external reference is linked to a file. If you delete it, the file will be deleted as well.',
        ) : t_i18n('Do you want to delete this external reference?')}
        isWarning={isExternalReferenceAttachment}
      />
    </>
  );
};

export default ExternalReferenceDeletion;
