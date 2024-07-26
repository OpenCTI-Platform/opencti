import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import ExternalReferenceEditionContainer from './ExternalReferenceEditionContainer';
import { ExternalReferencePopoverEditionQuery$data } from './__generated__/ExternalReferencePopoverEditionQuery.graphql';
import { deleteNodeFromId } from '../../../../utils/store';
import Transition from '../../../../components/Transition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

export const externalReferencePopoverDeletionMutation = graphql`
  mutation ExternalReferencePopoverDeletionMutation($id: ID!) {
    externalReferenceEdit(id: $id) {
      delete
    }
  }
`;

const externalReferenceEditionQuery = graphql`
  query ExternalReferencePopoverEditionQuery($id: String!) {
    externalReference(id: $id) {
      ...ExternalReferenceEditionContainer_externalReference
    }
  }
`;

interface ExternalReferencePopoverProps {
  id: string;
  objectId?: string;
  handleRemove: (() => void) | undefined;
  isExternalReferenceAttachment?: boolean;
}

const ExternalReferencePopover: FunctionComponent<
  ExternalReferencePopoverProps
> = ({ id, objectId, handleRemove, isExternalReferenceAttachment }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const [displayEdit, setDisplayEdit] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [commit] = useApiMutation(externalReferencePopoverDeletionMutation);
  const handleClose = () => {
    setAnchorEl(null);
  };
  const handleCloseUpdate = () => {
    setDisplayEdit(false);
  };
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
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
        handleClose();
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
          </DialogContentText>
          <QueryRenderer
            query={externalReferenceEditionQuery}
            variables={{ id }}
            render={({
              props,
            }: {
              props: ExternalReferencePopoverEditionQuery$data;
            }) => {
              if (props && props.externalReference) {
                return (
                  <ExternalReferenceEditionContainer
                    externalReference={props.externalReference}
                    handleClose={handleCloseUpdate}
                    open={displayEdit}
                  />
                );
              }
              return <div />;
            }}
          />
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

export default ExternalReferencePopover;
