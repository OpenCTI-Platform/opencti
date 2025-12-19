import MoreVert from '@mui/icons-material/MoreVert';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import IconButton from '@common/button/IconButton';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import { PopoverProps } from '@mui/material/Popover';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { useParams } from 'react-router-dom';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';
import { commitMutation } from '../../../../relay/environment';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { deleteNode } from '../../../../utils/store';
import { CaseTemplateTasksLine_node$data } from './__generated__/CaseTemplateTasksLine_node.graphql';
import { CaseTemplateTasksLinesPaginationQuery$data } from './__generated__/CaseTemplateTasksLinesPaginationQuery.graphql';
import CaseTemplateTasksEdition from './CaseTemplateTasksEdition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

const caseTemplateTasksPopoverDeletionMutation = graphql`
  mutation CaseTemplateTasksPopoverDeletionMutation($id: ID!) {
    taskTemplateDelete(id: $id)
  }
`;

const caseTemplateTasksPopoverUnlinkMutation = graphql`
  mutation CaseTemplateTasksPopoverUnlinkMutation($id: ID!, $toId: StixRef!) {
    caseTemplateRelationDelete(id: $id, toId: $toId, relationship_type: "template-task") {
      id
      ...CaseTemplateLine_node
    }
  }
`;

interface CaseTemplateTasksPopoverProps {
  task: CaseTemplateTasksLine_node$data;
  paginationOptions: CaseTemplateTasksLinesPaginationQuery$data;
}

const CaseTemplateTasksPopover: FunctionComponent<CaseTemplateTasksPopoverProps> = ({
  paginationOptions,
  task,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const { caseTemplateId } = useParams() as { caseTemplateId: string };

  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const [displayUnlink, setDisplayUnlink] = useState<boolean>(false);
  const [unlinking, setUnlinking] = useState<boolean>(false);

  const [commitUnlink] = useApiMutation(caseTemplateTasksPopoverUnlinkMutation);

  const handleOpen = (event: React.MouseEvent) => setAnchorEl(event.currentTarget);

  const handleClose = () => setAnchorEl(null);

  const deletion = useDeletion({ handleClose });

  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };

  const handleCloseUpdate = () => setDisplayUpdate(false);
  const { setDeleting, handleOpenDelete, handleCloseDelete } = deletion;

  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: caseTemplateTasksPopoverDeletionMutation,
      variables: {
        id: task.id,
      },
      updater: (store: RecordSourceSelectorProxy) => deleteNode(
        store,
        'Pagination_caseTemplate__taskTemplates',
        paginationOptions,
        task.id,
      ),
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
      setSubmitting: undefined,
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
        id: caseTemplateId,
        toId: task.id,
      },
      updater: (store: RecordSourceSelectorProxy) => deleteNode(
        store,
        'Pagination_caseTemplate__taskTemplates',
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
    <div className={classes.container}>
      <IconButton onClick={handleOpen} aria-haspopup="true" color="primary">
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenUpdate}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={handleOpenUnlink}>{t_i18n('Unlink')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      <Drawer
        open={displayUpdate}
        title={t_i18n('Update a task template')}
        onClose={handleCloseUpdate}
      >
        <CaseTemplateTasksEdition task={task} />
      </Drawer>
      <Dialog
        open={displayUnlink}
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseUnlink}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to unlink this task template ?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button variant="secondary" onClick={handleCloseUnlink} disabled={unlinking}>
            {t_i18n('Cancel')}
          </Button>
          <Button onClick={submitUnlink} disabled={unlinking}>
            {t_i18n('Unlink')}
          </Button>
        </DialogActions>
      </Dialog>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this task?')}
      />
    </div>
  );
};

export default CaseTemplateTasksPopover;
