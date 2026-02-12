import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import MoreVert from '@mui/icons-material/MoreVert';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import { useState } from 'react';
import DeleteDialog from '../../../../components/DeleteDialog';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { EXPLORE_EXUPDATE } from '../../../../utils/hooks/useGranted';
import handleWidgetExportJson from '../../../../utils/widget/widgetExportHandler';
import WorkspaceWidgetConfig from './WorkspaceWidgetConfig';

const WorkspaceWidgetPopover = ({
  onUpdate,
  onDuplicate,
  onDelete,
  widget,
  workspace,
}) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayDuplicate, setDisplayDuplicate] = useState(false);

  const handleClose = () => {
    setAnchorEl(null);
  };

  const deletion = useDeletion({ handleClose });
  const { handleOpenDelete } = deletion;

  const handleOpenDuplicate = () => {
    setDisplayDuplicate(true);
    handleClose();
  };

  const handleExportWidget = () => {
    handleWidgetExportJson(workspace.id, widget);
  };

  return (
    <>
      <IconButton
        onClick={(event) => {
          event.stopPropagation();
          event.preventDefault();
          setAnchorEl(event.currentTarget);
        }}
        aria-haspopup="true"
        size="small"
        className="noDrag"
        color="primary"
        aria-label={t_i18n('Widget popover of actions')}
      >
        <MoreVert fontSize="small" />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        keepMounted={true}
        onClose={() => setAnchorEl(null)}
        className="noDrag"
      >
        <Security needs={[EXPLORE_EXUPDATE]}>
          <WorkspaceWidgetConfig
            closeMenu={() => setAnchorEl(null)}
            onComplete={onUpdate}
            widget={widget}
            data={workspace}
          />
          <MenuItem onClick={handleExportWidget}>{t_i18n('Export')}</MenuItem>
          <MenuItem onClick={handleOpenDuplicate}>{t_i18n('Duplicate')}</MenuItem>
          <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
        </Security>
      </Menu>
      <DeleteDialog
        deletion={deletion}
        submitDelete={onDelete}
        message={t_i18n('Do you want to delete this widget?')}
      />
      <Dialog
        open={displayDuplicate}
        onClose={() => setDisplayDuplicate(false)}
        className="noDrag"
        title={t_i18n('Are you sure?')}
      >
        <DialogContentText>
          {t_i18n('Do you want to duplicate this widget?')}
        </DialogContentText>
        <DialogActions>
          <Button variant="secondary" onClick={() => setDisplayDuplicate(false)}>
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={() => {
              setDisplayDuplicate(false);
              onDuplicate(widget);
            }}
          >
            {t_i18n('Duplicate')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default WorkspaceWidgetPopover;
