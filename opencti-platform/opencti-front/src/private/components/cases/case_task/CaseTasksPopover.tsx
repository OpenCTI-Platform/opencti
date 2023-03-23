import { Close, MoreVertOutlined } from '@mui/icons-material';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import Transition from '../../../../components/Transition';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { deleteNode } from '../../../../utils/store';
import { CaseTasksLine_data$data } from '../__generated__/CaseTasksLine_data.graphql';
import { CaseTasksLinesQuery$variables } from '../__generated__/CaseTasksLinesQuery.graphql';
import CaseTaskEdition from './CaseTaskEdition';

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
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  formContainer: {
    padding: '10px 20px 20px 20px',
  },
}));

const caseTasksPopoverDeletionMutation = graphql`
  mutation CaseTasksPopoverCaseDeletionMutation($id: ID!) {
    caseTaskDelete(id: $id)
  }
`;

const caseTasksPopoverUnlinkMutation = graphql`
  mutation CaseTasksPopoverUnlinkMutation($id: ID!, $toId: StixRef!) {
    stixDomainObjectEdit(id: $id){
      relationDelete(toId: $toId, relationship_type: "object") {
        id
      }
    }
  }
`;

interface CaseTasksPopoverProps {
  task: CaseTasksLine_data$data,
  paginationOptions: CaseTasksLinesQuery$variables
  caseId: string
}

const CaseTasksPopover: FunctionComponent<CaseTasksPopoverProps> = ({
  task,
  paginationOptions,
  caseId,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [commit] = useMutation(caseTasksPopoverDeletionMutation);

  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const [update, setOpenUpdate] = useState(false);
  const [displayUnlink, setDisplayUnlink] = useState<boolean>(false);
  const [unlinking, setUnlinking] = useState<boolean>(false);

  const [commitUnlink] = useMutation(caseTasksPopoverUnlinkMutation);

  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const {
    deleting,
    handleOpenDelete,
    displayDelete,
    handleCloseDelete,
    setDeleting,
  } = useDeletion({ handleClose });

  const handleOpenUpdate = () => {
    setOpenUpdate(true);
    setAnchorEl(null);
  };

  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id: task.id,
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_caseTasks', paginationOptions, task.id);
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
    });
  };

  const handleOpenUnlink = () => {
    setDisplayUnlink(true);
    handleClose();
  };

  const handleCloseUnlink = () => setDisplayUnlink(false);

  const submitUnlink = () => {
    setUnlinking(true);
    commitUnlink({
      variables: {
        id: task.id,
        toId: caseId,
      },
      updater: (store: RecordSourceSelectorProxy) => deleteNode(
        store,
        'Pagination_caseTasks',
        paginationOptions,
        task.id,
      ),
      onCompleted: () => {
        setUnlinking(false);
        handleCloseUnlink();
      },
    });
  };

  return (
    <span className={classes.container}>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        style={{ marginTop: 3 }}
        size="large"
      >
        <MoreVertOutlined />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenUpdate}>{t('Update')}</MenuItem>
        <MenuItem onClick={handleOpenUnlink}>{t('Unlink')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t('Delete')}</MenuItem>
      </Menu>
      <Drawer
        open={update}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={() => setOpenUpdate(false)}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={() => setOpenUpdate(false)}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">
            {t('Update a task')}
          </Typography>
        </div>
        <div className={classes.formContainer}>
          <CaseTaskEdition task={task} />
        </div>
      </Drawer>
      <Dialog
        open={displayUnlink}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseUnlink}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to unlink this task ?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseUnlink} disabled={unlinking}>
            {t('Cancel')}
          </Button>
          <Button color="secondary" onClick={submitUnlink} disabled={unlinking}>
            {t('Unlink')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayDelete}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to delete this task ?')}
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
    </span>
  );
};

export default CaseTasksPopover;
