/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { useState } from 'react';
import { graphql } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import makeStyles from '@mui/styles/makeStyles';
import { useNavigate } from 'react-router-dom';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import PlaybookEdition, { playbookMutationFieldPatch } from './PlaybookEdition';
import { deleteNode } from '../../../../utils/store';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';
import stopEvent from '../../../../utils/domEvent';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

const playbookPopoverDeletionMutation = graphql`
  mutation PlaybookPopoverDeletionMutation($id: ID!) {
    playbookDelete(id: $id)
  }
`;

const playbookEditionQuery = graphql`
  query PlaybookPopoverEditionQuery($id: String!) {
    playbook(id: $id) {
      id
      name
      playbook_running
      playbook_definition
    }
  }
`;

const PlaybookPopover = (props) => {
  const { playbookId, running, paginationOptions } = props;
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayUpdate, setDisplayUpdate] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [displayStart, setDisplayStart] = useState(false);
  const [starting, setStarting] = useState(false);
  const [displayStop, setDisplayStop] = useState(false);
  const [stopping, setStopping] = useState(false);
  const handleOpen = (event) => {
    stopEvent(event);
    setAnchorEl(event.currentTarget);
  };
  const handleClose = (event) => {
    stopEvent(event);
    setAnchorEl(null);
  };
  const handleOpenUpdate = (event) => {
    setDisplayUpdate(true);
    handleClose(event);
  };
  const handleOpenDelete = (event) => {
    setDisplayDelete(true);
    handleClose(event);
  };
  const handleCloseDelete = (event) => {
    stopEvent(event);
    setDisplayDelete(false);
  };
  const handleOpenStart = (event) => {
    setDisplayStart(true);
    handleClose(event);
  };
  const handleCloseStart = (event) => {
    setDisplayStart(false);
    stopEvent(event);
  };
  const handleOpenStop = (event) => {
    setDisplayStop(true);
    handleClose(event);
  };
  const handleCloseStop = (event) => {
    setDisplayStop(false);
    stopEvent(event);
  };
  const submitDelete = (event) => {
    setDeleting(true);
    stopEvent(event);
    commitMutation({
      mutation: playbookPopoverDeletionMutation,
      variables: {
        id: playbookId,
      },
      updater: (store) => {
        if (paginationOptions) {
          deleteNode(
            store,
            'Pagination_playbooks',
            paginationOptions,
            playbookId,
          );
        }
      },
      onCompleted: () => {
        setDeleting(false);
        if (!paginationOptions) {
          navigate('/dashboard/data/processing/automation');
        }
        setDisplayDelete(true);
      },
    });
  };
  const submitStart = (event) => {
    setStarting(true);
    stopEvent(event);
    commitMutation({
      mutation: playbookMutationFieldPatch,
      variables: {
        id: playbookId,
        input: { key: 'playbook_running', value: ['true'] },
      },
      onCompleted: () => {
        setStarting(false);
        setDisplayStart(false);
      },
    });
  };
  const submitStop = (event) => {
    setStopping(true);
    stopEvent(event);
    commitMutation({
      mutation: playbookMutationFieldPatch,
      variables: {
        id: playbookId,
        input: { key: 'playbook_running', value: ['false'] },
      },
      onCompleted: () => {
        setStopping(false);
        setDisplayStop(false);
      },
    });
  };
  return (
    <div className={classes.container}>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        size="large"
        color="primary"
      >
        <MoreVert />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        {running ? (
          <MenuItem onClick={handleOpenStop}>{t_i18n('Stop')}</MenuItem>
        ) : (
          <MenuItem onClick={handleOpenStart}>{t_i18n('Start')}</MenuItem>
        )}
        <MenuItem onClick={handleOpenUpdate}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      <QueryRenderer
        query={playbookEditionQuery}
        variables={{ id: playbookId }}
        render={({ props: resultProps }) => {
          if (resultProps) {
            return (
              <PlaybookEdition
                playbook={resultProps.playbook}
                handleClose={() => setDisplayUpdate(false)}
                open={displayUpdate}
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
        onClose={() => setDisplayDelete(false)}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this playbook?')}
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
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayStart}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={() => setDisplayStart(false)}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to start this playbook?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseStart} disabled={starting}>
            {t_i18n('Cancel')}
          </Button>
          <Button onClick={submitStart} color="secondary" disabled={starting}>
            {t_i18n('Start')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayStop}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={() => setDisplayStop(false)}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to stop this playbook?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseStop} disabled={stopping}>
            {t_i18n('Cancel')}
          </Button>
          <Button onClick={submitStop} color="secondary" disabled={stopping}>
            {t_i18n('Stop')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default PlaybookPopover;
