/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
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
import { useNavigate } from 'react-router-dom-v5-compat';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import Loader from '../../../../components/Loader';
import PlaybookEdition, { playbookMutationFieldPatch } from './PlaybookEdition';
import { deleteNode } from '../../../../utils/store';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';

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
      ...PlaybookEdition_playbook
    }
  }
`;

const PlaybookPopover = (props) => {
  const { playbookId, running, paginationOptions } = props;
  const classes = useStyles();
  const { t } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayUpdate, setDisplayUpdate] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [displayStart, setDisplayStart] = useState(false);
  const [starting, setStarting] = useState(false);
  const [displayStop, setDisplayStop] = useState(false);
  const [stopping, setStopping] = useState(false);
  const handleOpenUpdate = () => {
    setAnchorEl(null);
    setDisplayUpdate(true);
  };
  const handleOpenDelete = () => {
    setAnchorEl(null);
    setDisplayDelete(true);
  };
  const handleOpenStart = () => {
    setAnchorEl(null);
    setDisplayStart(true);
  };
  const handleOpenStop = () => {
    setAnchorEl(null);
    setDisplayStop(true);
  };
  const submitDelete = () => {
    setDeleting(true);
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
  const submitStart = () => {
    setStarting(true);
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
  const submitStop = () => {
    setStopping(true);
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
        onClick={(event) => setAnchorEl(event.currentTarget)}
        aria-haspopup="true"
        style={{ marginTop: 3 }}
        size="large"
      >
        <MoreVert />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={() => setAnchorEl(null)}
      >
        {running ? (
          <MenuItem onClick={handleOpenStop}>{t('Stop')}</MenuItem>
        ) : (
          <MenuItem onClick={handleOpenStart}>{t('Start')}</MenuItem>
        )}
        <MenuItem onClick={handleOpenUpdate}>{t('Update')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t('Delete')}</MenuItem>
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
          return <Loader variant="inElement" />;
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
            {t('Do you want to delete this playbook?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDisplayDelete(false)} disabled={deleting}>
            {t('Cancel')}
          </Button>
          <Button color="secondary" onClick={submitDelete} disabled={deleting}>
            {t('Delete')}
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
            {t('Do you want to start this playbook?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDisplayStart(false)} disabled={starting}>
            {t('Cancel')}
          </Button>
          <Button onClick={submitStart} color="secondary" disabled={starting}>
            {t('Start')}
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
            {t('Do you want to stop this playbook?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDisplayStop(false)} disabled={stopping}>
            {t('Cancel')}
          </Button>
          <Button onClick={submitStop} color="secondary" disabled={stopping}>
            {t('Stop')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default PlaybookPopover;
