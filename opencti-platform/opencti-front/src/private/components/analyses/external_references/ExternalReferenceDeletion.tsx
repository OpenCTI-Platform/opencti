import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import { useNavigate } from 'react-router-dom';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { useFormatter } from '../../../../components/i18n';
import { deleteNodeFromId } from '../../../../utils/store';
import Transition from '../../../../components/Transition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

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
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_External-Reference') },
  });
  const [commit] = useApiMutation(
    externalReferenceDeletionDeleteMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );
  const handleOpenDelete = () => {
    setDisplayDelete(true);
  };
  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };
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
    <React.Fragment>
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
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayDelete}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this external reference?')}
            {isExternalReferenceAttachment && (
              <Alert
                severity="warning"
                variant="outlined"
                style={{ position: 'relative', marginTop: 20 }}
              >
                {t_i18n(
                  'This external reference is linked to a file. If you delete it, the file will be deleted as well.',
                )}
              </Alert>
            )}
          </DialogContentText>
          {isExternalReferenceAttachment && (
            <Alert
              severity="warning"
              variant="outlined"
              style={{ position: 'relative', marginTop: 20 }}
            >
              {t_i18n(
                'This external reference is linked to a file. If you delete it, the file will be deleted as well.',
              )}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete} disabled={deleting}>
            {t_i18n('Cancel')}
          </Button>
          <Button color="secondary" onClick={submitDelete} disabled={deleting}>
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </React.Fragment>
  );
};

export default ExternalReferenceDeletion;
