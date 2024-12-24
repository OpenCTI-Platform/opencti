import React, { FunctionComponent, useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import ToggleButton from '@mui/material/ToggleButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import StixCoreObjectEnrollPlaybook from '@components/common/stix_core_objects/StixCoreObjectEnrollPlaybook';
import StixCoreObjectEnrichment from '@components/common/stix_core_objects/StixCoreObjectEnrichment';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { noteEditionQuery } from './NoteEdition';
import NoteEditionContainer from './NoteEditionContainer';
import Security, { CollaborativeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { StixCoreObjectOrStixCoreRelationshipNoteCard_node$data } from './__generated__/StixCoreObjectOrStixCoreRelationshipNoteCard_node.graphql';
import Transition from '../../../../components/Transition';
import { NoteEditionContainerQuery$data } from './__generated__/NoteEditionContainerQuery.graphql';
import { deleteNode } from '../../../../utils/store';
import { StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables } from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCardsQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useHelper from '../../../../utils/hooks/useHelper';

const NotePopoverDeletionMutation = graphql`
  mutation NotePopoverDeletionMutation($id: ID!) {
    noteEdit(id: $id) {
      delete
    }
  }
`;

interface NotePopoverProps {
  id?: string;
  handleOpenRemoveExternal?: () => void;
  size?: 'medium' | 'large' | 'small' | undefined;
  note: StixCoreObjectOrStixCoreRelationshipNoteCard_node$data;
  paginationOptions: StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables;
  variant?: string;
}

const NotePopover: FunctionComponent<NotePopoverProps> = ({
  id,
  handleOpenRemoveExternal,
  size,
  note,
  paginationOptions,
  variant,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayDelete, setDisplayDelete] = useState<boolean>(false);
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const [displayEnrichment, setDisplayEnrichment] = useState<boolean>(false);
  const [displayEnroll, setDisplayEnroll] = useState(false);
  const [deleting, setDeleting] = useState<boolean>(false);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const handleOpen = (event: React.MouseEvent<HTMLElement>) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };
  const handleCloseDelete = () => setDisplayDelete(false);
  const [commit] = useApiMutation(NotePopoverDeletionMutation);
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      updater: (store) => {
        if (paginationOptions) {
          deleteNode(store, 'Pagination_notes', paginationOptions, note.id);
        }
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        if (handleOpenRemoveExternal) {
          handleCloseDelete();
        } else {
          navigate('/dashboard/analyses/notes');
        }
      },
    });
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const handleCloseEdit = () => setDisplayEdit(false);
  const handleOpenRemove = () => {
    if (handleOpenRemoveExternal) {
      handleOpenRemoveExternal();
    }
    handleClose();
  };
  const handleOpenEnrichment = () => {
    setDisplayEnrichment(true);
    handleClose();
  };
  const handleCloseEnrichment = () => {
    setDisplayEnrichment(false);
  };
  const handleOpenEnroll = () => {
    setDisplayEnroll(true);
    handleClose();
  };
  const handleCloseEnroll = () => {
    setDisplayEnroll(false);
  };

  return isFABReplaced
    ? (<></>)
    : (
      <>
        {variant === 'inLine' ? (
          <IconButton
            onClick={handleOpen}
            aria-haspopup="true"
            size={size || 'large'}
            style={{ marginTop: size === 'small' ? -3 : 3 }}
            color="primary"
          >
            <MoreVert />
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
          <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
          {handleOpenRemoveExternal && (
            <MenuItem onClick={handleOpenRemove}>
              {t_i18n('Remove from this entity')}
            </MenuItem>
          )}
          <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
            <MenuItem onClick={handleOpenEnrichment}>
              {t_i18n('Enrich')}
            </MenuItem>
          </Security>
          <MenuItem onClick={handleOpenEnroll}>{t_i18n('Enroll in playbook')}</MenuItem>
          <CollaborativeSecurity
            data={note}
            needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}
          >
            <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
          </CollaborativeSecurity>
        </Menu>
        <StixCoreObjectEnrichment stixCoreObjectId={id} open={displayEnrichment} handleClose={handleCloseEnrichment} />
        <StixCoreObjectEnrollPlaybook stixCoreObjectId={id} open={displayEnroll} handleClose={handleCloseEnroll} />
        <Dialog
          open={displayDelete}
          PaperProps={{ elevation: 1 }}
          TransitionComponent={Transition}
          onClose={handleCloseDelete}
        >
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to delete this note?')}
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
        <QueryRenderer
          query={noteEditionQuery}
          variables={{ id }}
          render={({ props }: { props: NoteEditionContainerQuery$data }) => {
            if (props && props.note) {
              return (
                <NoteEditionContainer
                  note={props.note}
                  handleClose={handleCloseEdit}
                  open={displayEdit}
                />
              );
            }
            return <div />;
          }}
        />
      </>
    );
};

export default NotePopover;
