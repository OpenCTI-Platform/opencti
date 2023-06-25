import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import React, { FunctionComponent } from 'react';
import { useFormatter } from './i18n';
import Transition from './Transition';

interface ExternalLinkPopoverProps {
  displayExternalLink: boolean;
  externalLink: string | URL | undefined;
  setDisplayExternalLink: (value: boolean) => void;
  setExternalLink: (value: string | URL | undefined) => void;
}

const ExternalLinkPopover: FunctionComponent<ExternalLinkPopoverProps> = ({
  displayExternalLink,
  externalLink,
  setDisplayExternalLink,
  setExternalLink,
}) => {
  const { t } = useFormatter();
  const handleCloseExternalLink = () => {
    setDisplayExternalLink(false);
    setExternalLink(undefined);
  };
  const handleBrowseExternalLink = () => {
    window.open(externalLink, '_blank');
    setDisplayExternalLink(false);
    setExternalLink(undefined);
  };
  return (
    <Dialog
      PaperProps={{ elevation: 1 }}
      open={displayExternalLink}
      keepMounted={true}
      TransitionComponent={Transition}
      onClose={handleCloseExternalLink}
    >
      <DialogContent>
        <DialogContentText>
          {t('Do you want to browse this external link?')}
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleCloseExternalLink}>{t('Cancel')}</Button>
        <Button color="secondary" onClick={handleBrowseExternalLink}>
          {t('Browse the link')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ExternalLinkPopover;
