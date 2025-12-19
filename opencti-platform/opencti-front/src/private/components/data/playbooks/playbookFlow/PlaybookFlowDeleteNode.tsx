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

import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import React from 'react';
import Transition from '../../../../../components/Transition';
import { useFormatter } from '../../../../../components/i18n';

interface PlaybookFlowDeleteNodeProps {
  action: string | null;
  setAction: (val: null) => void;
  selectedNode: unknown;
  setSelectedNode: (val: null) => void;
  deleteNode: () => void;
}

const PlaybookFlowDeleteNode = ({
  action,
  setAction,
  selectedNode,
  setSelectedNode,
  deleteNode,
}: PlaybookFlowDeleteNodeProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Dialog
      slotProps={{ paper: { elevation: 1 } }}
      open={selectedNode !== null && action === 'delete'}
      keepMounted={true}
      slots={{ transition: Transition }}
      onClose={() => {
        setSelectedNode(null);
        setAction(null);
      }}
    >
      <DialogTitle>
        {t_i18n('Are you sure?')}
      </DialogTitle>
      <DialogContent>
        <DialogContentText>
          {t_i18n('Do you want to delete this node?')}
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button
          variant="secondary"
          onClick={() => {
            setSelectedNode(null);
            setAction(null);
          }}
        >
          {t_i18n('Cancel')}
        </Button>
        <Button onClick={deleteNode}>
          {t_i18n('Confirm')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default PlaybookFlowDeleteNode;
