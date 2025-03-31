import React, { UIEvent, useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogContentText, IconButton, Menu, MenuItem } from '@mui/material';
import { MoreVert } from '@mui/icons-material';
import { graphql } from 'react-relay';
import { PopoverProps } from '@mui/material/Popover';
import { ImportWorkbenchesContentFileLine_file$data } from '@components/data/import/__generated__/ImportWorkbenchesContentFileLine_file.graphql';
import { ImportWorkbenchesContentQuery$variables } from '@components/data/import/__generated__/ImportWorkbenchesContentQuery.graphql';
import { ImportFilesContentFileLine_file$data } from '@components/data/import/__generated__/ImportFilesContentFileLine_file.graphql';
import { ImportFilesContentQuery$variables } from '@components/data/import/__generated__/ImportFilesContentQuery.graphql';
import { ImportActionsPopoverDeleteMutation } from '@components/common/files/__generated__/ImportActionsPopoverDeleteMutation.graphql';
import { ProgressUpload } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import ImportWorksDrawer from '@components/common/files/ImportWorksDrawer';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Transition from '../../../../components/Transition';
import { APP_BASE_PATH, MESSAGING$ } from '../../../../relay/environment';
import stopEvent from '../../../../utils/domEvent';
import { RelayError } from '../../../../relay/relayTypes';
import { deleteNode } from '../../../../utils/store';
import { useFormatter } from '../../../../components/i18n';

export const importActionsPopoverDeleteMutation = graphql`
  mutation ImportActionsPopoverDeleteMutation($fileName: String) {
    deleteImport(fileName: $fileName)
  }
`;

interface ImportActionsPopoverProps {
  file: ImportWorkbenchesContentFileLine_file$data | ImportFilesContentFileLine_file$data;
  paginationOptions: ImportWorkbenchesContentQuery$variables | ImportFilesContentQuery$variables;
  paginationKey: 'Pagination_global_pendingFiles' | 'Pagination_global_importFiles';
}

const ImportActionsPopover = ({
  file,
  paginationOptions,
  paginationKey,
}: ImportActionsPopoverProps) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();
  const [openDelete, setOpenDelete] = useState(false);
  const [openWorks, setOpenWorks] = useState(false);
  const [commitDeletion] = useApiMutation<ImportActionsPopoverDeleteMutation>(importActionsPopoverDeleteMutation, undefined, {
    successMessage: t_i18n('', {
      id: '... successfully deleted',
      values: { entity_type: t_i18n('Workbench') },
    }),
  });

  const handleOpen = (event: UIEvent) => {
    stopEvent(event);
    setAnchorEl(event.currentTarget);
  };

  const handleClose = (event: UIEvent) => {
    stopEvent(event);
    setAnchorEl(null);
  };

  const handleDeleteOpen = (event: UIEvent) => {
    setOpenDelete(true);
    handleClose(event);
  };

  const handleDeleteClose = (event: UIEvent) => {
    stopEvent(event);
    setOpenDelete(false);
  };

  const submitDelete = (event: UIEvent) => {
    stopEvent(event);

    commitDeletion({
      variables: { fileName: file.id },
      onCompleted: () => {
        handleClose(event);
        handleDeleteClose(event);
      },
      onError: (error) => {
        MESSAGING$.notifyRelayError(error as unknown as RelayError);
        handleClose(event);
        handleDeleteClose(event);
      },
      updater: (store) => {
        deleteNode(store, paginationKey, paginationOptions, file.id);
      },
    });
  };

  return (
    <div style={{ marginLeft: -40 }}>
      <Tooltip title={t_i18n('Show the imports')}>
        <IconButton
          onClick={(event) => {
            stopEvent(event);
            setOpenWorks(true);
          }}
          aria-haspopup="true"
          color={file.works?.length ? 'primary' : 'inherit'}
          size="large"
        >
          <ProgressUpload fontSize="small"/>
        </IconButton>
      </Tooltip>
      <IconButton onClick={handleOpen} size="large" color="primary">
        <MoreVert fontSize="small"/>
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem
          onClick={(event: UIEvent) => {
            stopEvent(event);
            window.location.pathname = `${APP_BASE_PATH}/storage/get/${encodeURIComponent(file.id)}`;
          }}
          disabled={file.uploadStatus === 'progress'}
        >
          {t_i18n('Download')}
        </MenuItem>
        <MenuItem onClick={handleDeleteOpen} disabled={file.uploadStatus === 'progress'}>
          {t_i18n('Delete')}
        </MenuItem>
      </Menu>
      <Dialog open={openDelete} onClose={handleDeleteClose} slots={{ transition: Transition }}>
        <DialogContent>
          <DialogContentText>
            {`${t_i18n('Do you want to delete this ')} ${paginationKey === 'Pagination_global_pendingFiles' ? t_i18n('workbench') : t_i18n('file')}?`}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleDeleteClose}>{t_i18n('Cancel')}</Button>
          <Button onClick={submitDelete} color="secondary">{t_i18n('Delete')}</Button>
        </DialogActions>
      </Dialog>
      {openWorks && (<ImportWorksDrawer open={openWorks} onClose={() => setOpenWorks(false)} file={file}/>)}
    </div>
  );
};

export default ImportActionsPopover;
