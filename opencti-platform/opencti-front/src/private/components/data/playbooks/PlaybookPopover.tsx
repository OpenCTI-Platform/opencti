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

import React, { useState, UIEvent } from 'react';
import { graphql } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import ToggleButton from '@mui/material/ToggleButton';
import { useNavigate } from 'react-router-dom';
import fileDownload from 'js-file-download';
import { PlaybooksLinesPaginationQuery$variables } from '@components/data/__generated__/PlaybooksLinesPaginationQuery.graphql';
import PlaybookPopoverToggleDialog from './PlaybookPopoverToggleDialog';
import { fetchQuery } from '../../../../relay/environment';
import { deleteNode } from '../../../../utils/store';
import { useFormatter } from '../../../../components/i18n';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import stopEvent from '../../../../utils/domEvent';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { resolveLink } from '../../../../utils/Entity';
import { PlaybookPopoverExportQuery$data } from './__generated__/PlaybookPopoverExportQuery.graphql';
import { PlaybookPopoverDeletionMutation } from './__generated__/PlaybookPopoverDeletionMutation.graphql';
import { PlaybookPopoverDuplicateMutation } from './__generated__/PlaybookPopoverDuplicateMutation.graphql';

const playbookPopoverDeletionMutation = graphql`
  mutation PlaybookPopoverDeletionMutation($id: ID!) {
    playbookDelete(id: $id)
  }
`;

const playbookPopoverDuplicateMutation = graphql`
  mutation PlaybookPopoverDuplicateMutation($id: ID!) {
    playbookDuplicate(id: $id)
  }
`;

const playbookExportQuery = graphql`
  query PlaybookPopoverExportQuery($id: String!) {
    playbook(id: $id) {
      name
      toConfigurationExport
    }
  }
`;

interface PlaybookPopoverProps {
  playbookId: string;
  running: boolean;
  paginationOptions?: PlaybooksLinesPaginationQuery$variables;
}

const PlaybookPopover = ({
  playbookId,
  running,
  paginationOptions,
}: PlaybookPopoverProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const [displayToggle, setDisplayToggle] = useState(false);

  const handleOpen = (event: UIEvent) => {
    stopEvent(event);
    setAnchorEl(event.currentTarget);
  };
  const handleClose = (event: UIEvent) => {
    stopEvent(event);
    setAnchorEl(null);
  };

  const handleOpenToggle = (event: UIEvent) => {
    handleClose(event);
    setDisplayToggle(true);
  };
  const handleCloseToggle = (event?: UIEvent) => {
    if (event) stopEvent(event);
    setDisplayToggle(false);
  };

  const deletion = useDeletion({ handleClose: () => setAnchorEl(null) });
  const { setDeleting, handleOpenDelete } = deletion;

  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Playbook') },
  });
  const [commitDelete] = useApiMutation<PlaybookPopoverDeletionMutation>(
    playbookPopoverDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const duplicatedSuccessMessage = t_i18n('', {
    id: '... successfully duplicated',
    values: { entity_type: t_i18n('entity_Playbook') },
  });
  const [commitDuplicate] = useApiMutation<PlaybookPopoverDuplicateMutation>(
    playbookPopoverDuplicateMutation,
    undefined,
    { successMessage: duplicatedSuccessMessage },
  );

  const exportPlaybook = async () => {
    const { playbook } = await fetchQuery(
      playbookExportQuery,
      { id: playbookId },
    ).toPromise() as PlaybookPopoverExportQuery$data;
    if (playbook) {
      const blob = new Blob([playbook.toConfigurationExport], { type: 'text/json' });
      const [day, month, year] = new Date().toLocaleDateString('fr-FR').split('/');
      const fileName = `${year}${month}${day}_playbook_${playbook.name}.json`;
      fileDownload(blob, fileName);
    }
  };

  const onExport = async (e: UIEvent) => {
    handleClose(e);
    await exportPlaybook();
  };

  // -- Duplication --
  const submitDuplicate = () => {
    commitDuplicate({
      variables: {
        id: playbookId,
      },
      onCompleted: (data) => {
        navigate(`${resolveLink('Playbook')}/${data.playbookDuplicate}`);
      },
    });
  };

  const submitDelete = (event: UIEvent) => {
    setDeleting(true);
    stopEvent(event);
    commitDelete({
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
        navigate('/dashboard/data/processing/automation');
      },
    });
  };

  const MoreVertButton = paginationOptions ? IconButton : ToggleButton;

  return (
    <>
      {/* eslint-disable-next-line @typescript-eslint/ban-ts-comment */}
      {/* @ts-ignore */}
      <MoreVertButton
        onClick={handleOpen}
        aria-haspopup="true"
        value="popover"
        color="primary"
        // size={paginationOptions ? 'medium' : 'small'}
      >
        {paginationOptions
          ? <MoreVert />
          : <MoreVert fontSize="small" color="primary" />}
      </MoreVertButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        {running
          ? <MenuItem onClick={handleOpenToggle}>{t_i18n('Stop')}</MenuItem>
          : <MenuItem onClick={handleOpenToggle}>{t_i18n('Start')}</MenuItem>
        }
        <MenuItem onClick={submitDuplicate}>{t_i18n('Duplicate')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
        <MenuItem onClick={onExport}>{t_i18n('Export')}</MenuItem>
      </Menu>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this playbook?')}
      />
      <PlaybookPopoverToggleDialog
        playbookRunning={running}
        playbookId={playbookId}
        showDialog={displayToggle}
        close={handleCloseToggle}
      />
    </>
  );
};

export default PlaybookPopover;
