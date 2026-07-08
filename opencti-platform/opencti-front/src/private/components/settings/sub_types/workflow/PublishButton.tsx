import React, { useRef, useState } from 'react';
import { ButtonGroup, ClickAwayListener, DialogActions, Grow, MenuItem, MenuList, Paper, Popper, Tooltip } from '@mui/material';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import CircleIcon from '@mui/icons-material/Circle';
import ArrowDropDownIcon from '@mui/icons-material/ArrowDropDown';
import { useFormatter } from '../../../../../components/i18n';

interface ValidationError {
  type: string;
  message: string;
  path?: Array<{ id: string; entity_type: string }> | null;
}

const BUTTON_WIDTH = 120;

interface ValidationStatus {
  published: boolean;
  validationErrors: ValidationError[];
}

interface PublishButtonProps {
  validationStatus: ValidationStatus | null;
  onPublish: () => void;
  onReset: () => void;
  onRestore: () => void;
  hasPublishedVersion: boolean;
  disabled?: boolean;
}

const PublishButton = ({
  validationStatus,
  onPublish,
  onReset,
  onRestore,
  hasPublishedVersion,
  disabled,
}: PublishButtonProps) => {
  const { t_i18n } = useFormatter();
  const anchorRef = useRef<HTMLDivElement>(null);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [restoreConfirmOpen, setRestoreConfirmOpen] = useState(false);

  const handleToggle = () => setDropdownOpen((prev) => !prev);

  const handleClose = (event: Event) => {
    if (anchorRef.current?.contains(event.target as HTMLElement)) return;
    setDropdownOpen(false);
  };

  const handleResetClick = () => {
    setDropdownOpen(false);
    setConfirmOpen(true);
  };

  const handleConfirmReset = () => {
    setConfirmOpen(false);
    onReset();
  };

  const handleRestoreClick = () => {
    setDropdownOpen(false);
    setRestoreConfirmOpen(true);
  };

  const handleConfirmRestore = () => {
    setRestoreConfirmOpen(false);
    onRestore();
  };

  if (!validationStatus) {
    return null;
  }

  const { published, validationErrors } = validationStatus;

  let mainButtonTooltip: string;
  let mainButtonIcon: React.ReactNode;
  let mainButtonDisabled: boolean;
  let mainButtonOnClick: (() => void) | undefined;

  if (published && validationErrors.length === 0) {
    mainButtonTooltip = t_i18n('Workflow is published');
    mainButtonIcon = <CircleIcon color="success" />;
    mainButtonDisabled = true;
    mainButtonOnClick = undefined;
  } else if (!published && validationErrors.length > 0) {
    mainButtonTooltip = t_i18n('Click to see validation errors');
    mainButtonIcon = <CircleIcon color="error" />;
    mainButtonDisabled = disabled ?? false;
    mainButtonOnClick = onPublish;
  } else {
    mainButtonTooltip = t_i18n('Click to publish this workflow version');
    mainButtonIcon = <CircleIcon color="warning" />;
    mainButtonDisabled = disabled ?? false;
    mainButtonOnClick = onPublish;
  }

  return (
    <>
      <Tooltip title={mainButtonTooltip} placement="top">
        <ButtonGroup ref={anchorRef} sx={{ display: 'flex' }}>
          <Button
            startIcon={mainButtonIcon}
            variant="secondary"
            onClick={mainButtonOnClick}
            disabled={mainButtonDisabled}
            sx={{ width: BUTTON_WIDTH, borderRadius: '4px 0 0 4px' }}
          >
            {published && validationErrors.length === 0 ? t_i18n('Published') : t_i18n('Publish')}
          </Button>
          <Button
            variant="secondary"
            onClick={handleToggle}
            sx={{ minWidth: '32px', px: 0, borderRadius: '0 4px 4px 0' }}
            aria-controls={dropdownOpen ? 'workflow-action-menu' : undefined}
            aria-expanded={dropdownOpen ? 'true' : undefined}
            aria-label={t_i18n('More workflow options')}
            aria-haspopup="menu"
          >
            <ArrowDropDownIcon fontSize="small" />
          </Button>
        </ButtonGroup>
      </Tooltip>
      <Popper
        sx={{ zIndex: 1 }}
        open={dropdownOpen}
        anchorEl={anchorRef.current}
        role={undefined}
        transition
        disablePortal
      >
        {({ TransitionProps, placement }) => (
          <Grow
            {...TransitionProps}
            style={{ transformOrigin: placement === 'bottom' ? 'center top' : 'center bottom' }}
          >
            <Paper>
              <ClickAwayListener onClickAway={handleClose}>
                <MenuList id="workflow-action-menu" autoFocusItem>
                  <MenuItem onClick={handleRestoreClick} disabled={published || !hasPublishedVersion}>
                    {t_i18n('Restore published version')}
                  </MenuItem>
                  <MenuItem onClick={handleResetClick}>
                    {t_i18n('Reset workflow')}
                  </MenuItem>
                </MenuList>
              </ClickAwayListener>
            </Paper>
          </Grow>
        )}
      </Popper>
      <Dialog
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        title={t_i18n('Reset workflow')}
        size="small"
      >
        {t_i18n('This will clear the draft workflow and keep the published workflow unchanged. Are you sure you want to start from scratch?')}
        <DialogActions>
          <Button variant="secondary" onClick={() => setConfirmOpen(false)}>
            {t_i18n('Cancel')}
          </Button>
          <Button intent="destructive" onClick={handleConfirmReset}>
            {t_i18n('Reset')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={restoreConfirmOpen}
        onClose={() => setRestoreConfirmOpen(false)}
        title={t_i18n('Restore published version')}
        size="small"
      >
        {t_i18n('This will replace the workflow with the last published version. All unpublished changes will be lost. Are you sure?')}
        <DialogActions>
          <Button variant="secondary" onClick={() => setRestoreConfirmOpen(false)}>
            {t_i18n('Cancel')}
          </Button>
          <Button intent="destructive" onClick={handleConfirmRestore}>
            {t_i18n('Restore')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default PublishButton;
