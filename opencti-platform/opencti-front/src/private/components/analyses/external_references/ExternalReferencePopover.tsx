import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Menu from '@mui/material/Menu';
import Alert from '@mui/material/Alert';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import { MoreVertOutlined } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import ToggleButton from '@mui/material/ToggleButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import ExternalReferenceEditionContainer from './ExternalReferenceEditionContainer';
import { ExternalReferencePopoverEditionQuery$data } from './__generated__/ExternalReferencePopoverEditionQuery.graphql';
import { deleteNodeFromId } from '../../../../utils/store';
import Transition from '../../../../components/Transition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useHelper from '../../../../utils/hooks/useHelper';

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
  variant?: string;
}

const ExternalReferencePopover: FunctionComponent<
ExternalReferencePopoverProps
> = ({ id, objectId, handleRemove, isExternalReferenceAttachment, variant }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const [displayEdit, setDisplayEdit] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [commit] = useApiMutation(externalReferencePopoverDeletionMutation);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };
  const handleOpenUpdate = () => {
    setDisplayEdit(true);
    handleClose();
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

  return (isFABReplaced && variant !== 'inLine')
    ? (<></>)
    : (
      <>
        {variant === 'inLine' ? (
          <IconButton
            onClick={handleOpen}
            aria-haspopup="true"
            style={{ marginTop: 3 }}
            size="large"
            color="primary"
          >
            <MoreVertOutlined />
          </IconButton>
        ) : (
          <ToggleButton
            value="popover"
            size="small"
            onClick={handleOpen}
          >
            <MoreVert fontSize="small" color="primary" />
          </ToggleButton>
        )}
        <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
          <MenuItem onClick={handleOpenUpdate}>{t_i18n('Update')}</MenuItem>
          {handleRemove && !isExternalReferenceAttachment && (
            <MenuItem
              onClick={() => {
                handleRemove();
                handleClose();
              }}
            >
              {t_i18n('Remove from this object')}
            </MenuItem>
          )}
          <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
        </Menu>
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
      </>
    );
};

export default ExternalReferencePopover;
