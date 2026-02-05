import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { OpenInNewOutlined } from '@mui/icons-material';
import { DialogActions, Typography } from '@mui/material';
import { FunctionComponent } from 'react';
import { useFormatter } from './i18n';

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
      open={displayExternalLink}
      onClose={handleCloseExternalLink}
      title={t_i18n('Do you want to browse this external link?')}
    >
      <Typography
        title={displayLinkStr} // complete URL in tooltip on hover
        sx={{ wordWrap: 'break-word', marginTop: 1 }}
      >
        {displayLinkCrop}
      </Typography>

      <DialogActions>
        <Button variant="secondary" onClick={handleCloseExternalLink}>{t_i18n('Cancel')}</Button>
        <Button
          startIcon={<OpenInNewOutlined fontSize="small" />}
          onClick={handleBrowseExternalLink}
        >
          {t_i18n('Browse the link')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ExternalLinkPopover;
