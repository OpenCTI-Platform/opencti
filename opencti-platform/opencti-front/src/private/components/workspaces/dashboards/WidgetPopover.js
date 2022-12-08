import React, { useState } from 'react';
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
import { useFormatter } from '../../../../components/i18n';
import Security, { EXPLORE_EXUPDATE } from '../../../../utils/Security';
import WidgetConfig from './WidgetConfig';
import Transition from '../../../../components/Transition';

const useStyles = makeStyles((theme) => ({
  container: {
    margin: 0,
    position: 'absolute',
    top: 0,
    right: 0,
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
}));

const StixCyberObservablePopover = ({
  onUpdate,
  onDuplicate,
  widget,
  onDelete,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [displayDuplicate, setDisplayDuplicate] = useState(false);
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    setAnchorEl(null);
  };
  const handleOpenDuplicate = () => {
    setDisplayDuplicate(true);
    setAnchorEl(null);
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
          <WidgetConfig
            closeMenu={() => setAnchorEl(null)}
            onComplete={onUpdate}
            widget={widget}
          />
          <MenuItem onClick={handleOpenDuplicate}>{t('Duplicate')}</MenuItem>
          <MenuItem onClick={handleOpenDelete}>{t('Delete')}</MenuItem>
        </Security>
      </Menu>
      <Dialog
        open={displayDelete}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={() => setDisplayDelete(false)}
        className="noDrag"
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to delete this widget?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDisplayDelete(false)}>{t('Cancel')}</Button>
          <Button onClick={onDelete} color="secondary">
            {t('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={displayDuplicate}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={() => setDisplayDuplicate(false)}
        className="noDrag"
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to duplicate this widget?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDisplayDelete(false)}>{t('Cancel')}</Button>
          <Button
            onClick={() => {
              setDisplayDuplicate(false);
              onDuplicate(widget);
            }}
            color="secondary"
          >
            {t('Duplicate')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default StixCyberObservablePopover;
