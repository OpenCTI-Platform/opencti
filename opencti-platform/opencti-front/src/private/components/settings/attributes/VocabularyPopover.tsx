import React, { FunctionComponent, useState } from 'react';
import Drawer from '@mui/material/Drawer';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@mui/material/IconButton';
import { MoreVertOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { PopoverProps } from '@mui/material/Popover';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { graphql, useMutation } from 'react-relay';
import VocabularyEdition from './VocabularyEdition';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { useVocabularyCategory_Vocabularynode$data } from '../../../../utils/hooks/__generated__/useVocabularyCategory_Vocabularynode.graphql';
import Transition from '../../../../components/Transition';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { deleteNode } from '../../../../utils/store';
import { LocalStorage } from '../../../../utils/hooks/useLocalStorage';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    margin: 0,
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

interface VocabularyPopoverProps {
  vocab: useVocabularyCategory_Vocabularynode$data;
  paginationOptions: LocalStorage;
  refetch: () => void;
}

const VocabularyPopoverDeletionMutation = graphql`
  mutation VocabularyPopoverDeletionMutation($id: ID!) {
    vocabularyDelete(id: $id)
  }
`;

const VocabularyPopover: FunctionComponent<VocabularyPopoverProps> = ({
  vocab,
  paginationOptions,
  refetch,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const handleOpen = (event: React.MouseEvent) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };
  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };
  const handleCloseUpdate = () => {
    setDisplayUpdate(false);
    refetch();
  };
  let deleteLabel = t('Delete');
  const deletable = !vocab.builtIn
    && (!vocab.category.fields.some(({ required }) => required)
      || vocab.usages === 0);
  if (!deletable) {
    if (vocab.builtIn) {
      deleteLabel = t('This item is built-in');
    } else {
      deleteLabel = t('Some fields in usage are mandatory');
    }
  }
  const {
    deleting,
    handleOpenDelete,
    displayDelete,
    handleCloseDelete,
    setDeleting,
  } = useDeletion({ handleClose });
  const [commit] = useMutation(VocabularyPopoverDeletionMutation);
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id: vocab.id,
      },
      updater: (store) => {
        deleteNode(
          store,
          'Pagination_vocabularies',
          paginationOptions,
          vocab.id,
        );
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        handleCloseDelete();
      },
    });
  };
  return (
    <div className={classes.container}>
      <IconButton onClick={handleOpen} aria-haspopup="true" size="large">
        <MoreVertOutlined />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenUpdate}>{t('Update')}</MenuItem>
        <MenuItem onClick={handleOpenDelete} disabled={!deletable}>
          {deleteLabel}
        </MenuItem>
      </Menu>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayDelete}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to delete this vocabulary?')}
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
        open={displayUpdate}
        anchor="right"
        sx={{ zIndex: 1202 }}
        elevation={1}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleCloseUpdate}
      >
        <VocabularyEdition vocab={vocab} handleClose={handleCloseUpdate} />
      </Drawer>
    </div>
  );
};

export default VocabularyPopover;
