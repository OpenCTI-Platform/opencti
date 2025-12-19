import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import React, { FunctionComponent } from 'react';
import { OpenInNewOutlined } from '@mui/icons-material';
import { useFormatter } from './i18n';
import Transition from './Transition';

interface ExternalLinkPopoverProps {
  displayExternalLink: boolean;
  externalLink: string | URL | undefined;
  setDisplayExternalLink: (value: boolean) => void;
  setExternalLink?: (value: string | URL | undefined) => void;
}

const ExternalLinkPopover: FunctionComponent<ExternalLinkPopoverProps> = ({
  displayExternalLink,
  externalLink,
  setDisplayExternalLink,
  setExternalLink,
}) => {
  const { t_i18n } = useFormatter();
  const handleCloseExternalLink = () => {
    setDisplayExternalLink(false);
    setExternalLink?.(undefined);
  };
  const handleBrowseExternalLink = () => {
    window.open(externalLink, '_blank');
    setDisplayExternalLink(false);
    setExternalLink?.(undefined);
  };

  const displayLinkStr = `${externalLink}`;
  const displayLinkCrop = displayLinkStr.length > 200 ? `${displayLinkStr.slice(0, 200)}...` : displayLinkStr;

  return (
    <Dialog
      slotProps={{ paper: { elevation: 1 } }}
      open={displayExternalLink}
      keepMounted={true}
      slots={{ transition: Transition }}
      onClose={handleCloseExternalLink}
    >
      <DialogContent>
        <DialogContentText>
          {t_i18n('Do you want to browse this external link?')}
        </DialogContentText>
        <DialogContentText
          title={displayLinkStr} // complete URL in tooltip on hover
          sx={{ wordWrap: 'break-word', marginTop: 1 }}
        >
          {displayLinkCrop}
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button variant="secondary" onClick={handleCloseExternalLink}>{t_i18n('Cancel')}</Button>
        <Button onClick={handleBrowseExternalLink}>
          {t_i18n('Browse the link')}
          <OpenInNewOutlined fontSize="small" sx={{ marginLeft: '2px' }} />
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ExternalLinkPopover;
