import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import makeStyles from '@mui/styles/makeStyles';
import handleWidgetExportJson from '../../../../utils/widget/widgetExportHandler';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { EXPLORE_EXUPDATE } from '../../../../utils/hooks/useGranted';
import WorkspaceWidgetConfig from './WorkspaceWidgetConfig';
import Transition from '../../../../components/Transition';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles({
  container: {
    margin: 0,
    position: 'absolute',
    top: 0,
    right: 0,
  },
});

const WorkspaceWidgetPopover = ({
  onUpdate,
  onDuplicate,
  widget,
  onDelete,
  workspace,
}) => {
  const classes = useStyles();
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
    <div className={classes.container}>
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
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={() => setDisplayDuplicate(false)}
        className="noDrag"
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to duplicate this widget?')}
          </DialogContentText>
        </DialogContent>
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
    </div>
  );
};

export default WorkspaceWidgetPopover;
