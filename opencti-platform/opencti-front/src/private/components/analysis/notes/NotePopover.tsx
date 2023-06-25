import React, { FunctionComponent, useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Drawer from '@mui/material/Drawer';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { useNavigate } from 'react-router-dom-v5-compat';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { noteEditionQuery } from './NoteEdition';
import NoteEditionContainer from './NoteEditionContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { CollaborativeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { Theme } from '../../../../components/Theme';
import { StixCoreObjectOrStixCoreRelationshipNoteCard_node$data } from './__generated__/StixCoreObjectOrStixCoreRelationshipNoteCard_node.graphql';
import Transition from '../../../../components/Transition';
import { NoteEditionContainerQuery$data } from './__generated__/NoteEditionContainerQuery.graphql';
import { deleteNode } from '../../../../utils/store';
import { StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables } from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCardsQuery.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    marginTop: 0,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
}));

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
}

const NotePopover: FunctionComponent<NotePopoverProps> = ({
  id,
  handleOpenRemoveExternal,
  size,
  note,
  paginationOptions,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayDelete, setDisplayDelete] = useState<boolean>(false);
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const [deleting, setDeleting] = useState<boolean>(false);
  const handleOpen = (event: React.MouseEvent<HTMLElement>) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };
  const handleCloseDelete = () => setDisplayDelete(false);
  const [commit] = useMutation(NotePopoverDeletionMutation);
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
          navigate('/dashboard/analysis/notes');
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

  return (
    <div className={classes.container}>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        size={size || 'large'}
        style={{ marginTop: size === 'small' ? -3 : 3 }}
      >
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenEdit}>{t('Update')}</MenuItem>
        {handleOpenRemoveExternal && (
          <MenuItem onClick={handleOpenRemove}>
            {t('Remove from this entity')}
          </MenuItem>
        )}
        <CollaborativeSecurity
          data={note}
          needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}
        >
          <MenuItem onClick={handleOpenDelete}>{t('Delete')}</MenuItem>
        </CollaborativeSecurity>
      </Menu>
      <Dialog
        open={displayDelete}
        PaperProps={{ elevation: 1 }}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to delete this note?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete} disabled={deleting}>
            {t('Cancel')}
          </Button>
          <Button color="secondary" onClick={submitDelete} disabled={deleting}>
            {t('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
      <Drawer
        open={displayEdit}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleCloseEdit}
      >
        <QueryRenderer
          query={noteEditionQuery}
          variables={{ id }}
          render={({ props }: { props: NoteEditionContainerQuery$data }) => {
            if (props && props.note) {
              return (
                <NoteEditionContainer
                  note={props.note}
                  handleClose={handleCloseEdit}
                />
              );
            }
            return <Loader variant={LoaderVariant.inElement} />;
          }}
        />
      </Drawer>
    </div>
  );
};

export default NotePopover;
