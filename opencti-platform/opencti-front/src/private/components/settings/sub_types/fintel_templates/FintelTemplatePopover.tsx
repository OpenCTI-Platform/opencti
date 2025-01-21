import MoreVert from '@mui/icons-material/MoreVert';
import React, { UIEvent, useState } from 'react';
import { MenuItem, Menu, PopoverProps, IconButton } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { graphql } from 'react-relay';
import { FintelTemplatePopoverExportQuery$data } from '@components/settings/sub_types/fintel_templates/__generated__/FintelTemplatePopoverExportQuery.graphql';
import fileDownload from 'js-file-download';
import useFintelTemplateDelete from './useFintelTemplateDelete';
import Transition from '../../../../../components/Transition';
import stopEvent from '../../../../../utils/domEvent';
import { useFormatter } from '../../../../../components/i18n';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import { fetchQuery } from '../../../../../relay/environment';

const fintelTemplatePopoverExportQuery = graphql`
  query FintelTemplatePopoverExportQuery($id: ID!) {
    fintelTemplate(id: $id) {
      name
      configuration_export
    }
  }
`;

interface FintelTemplatePopoverProps {
  onUpdate: () => void,
  onDeleteComplete?: () => void,
  entitySettingId: string,
  templateId: string,
  inline?: boolean
}

const FintelTemplatePopover = ({
  onUpdate,
  onDeleteComplete,
  entitySettingId,
  templateId,
  inline = true,
}: FintelTemplatePopoverProps) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();
  const [commitDeleteMutation, deleting] = useFintelTemplateDelete(entitySettingId);

  const {
    handleOpenDelete,
    displayDelete,
    handleCloseDelete,
  } = useDeletion({});

  const onOpenMenu = (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(e.currentTarget);
  };

  const onHandleOpenDelete = (e: UIEvent) => {
    stopEvent(e);
    handleOpenDelete();
  };

  const onCloseMenu = (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(undefined);
  };

  const onHandleCloseDelete = (e: UIEvent) => {
    stopEvent(e);
    handleCloseDelete();
    setAnchorEl(null);
  };

  const update = (e: UIEvent) => {
    stopEvent(e);
    onUpdate();
    onCloseMenu(e);
  };

  const onDelete = (e: UIEvent) => {
    stopEvent(e);
    if (!templateId) return;

    commitDeleteMutation(templateId, {
      variables: { id: templateId },
      onCompleted: () => {
        handleCloseDelete();
        onDeleteComplete?.();
      },
      onError: () => {
        handleCloseDelete();
      },
    });
  };

  const onExport = async (e: UIEvent) => {
    stopEvent(e);

    const { fintelTemplate } = await fetchQuery(
      fintelTemplatePopoverExportQuery,
      { id: templateId },
    ).toPromise() as FintelTemplatePopoverExportQuery$data;
    if (fintelTemplate) {
      const blob = new Blob([fintelTemplate.configuration_export], { type: 'text/json' });
      const [day, month, year] = new Date().toLocaleDateString('fr-FR').split('/');
      const fileName = `${year}${month}${day}_fintel_${fintelTemplate.name}.json`;
      fileDownload(blob, fileName);
    }
  };

  return (
    <>
      {inline ? (
        <IconButton onClick={onOpenMenu} aria-haspopup="true" color="primary">
          <MoreVert fontSize="small" />
        </IconButton>
      ) : (
        <Button
          onClick={onOpenMenu}
          aria-haspopup="true"
          className="icon-outlined"
          variant="outlined"
        >
          <MoreVert fontSize="small" />
        </Button>
      )}

      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={onCloseMenu}>
        <MenuItem onClick={update}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={onHandleOpenDelete}>{t_i18n('Delete')}</MenuItem>
        <MenuItem onClick={onExport}>{t_i18n('Export')}</MenuItem>
      </Menu>

      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayDelete}
        TransitionComponent={Transition}
        onClose={onHandleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this FINTEL template?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={onHandleCloseDelete} disabled={deleting}>
            {t_i18n('Cancel')}
          </Button>
          <Button color="secondary" onClick={onDelete} disabled={deleting}>
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default FintelTemplatePopover;
