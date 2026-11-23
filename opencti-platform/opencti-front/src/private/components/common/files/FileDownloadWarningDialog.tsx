import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import Alert from '@mui/material/Alert';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import React, { FunctionComponent } from 'react';
import { useFormatter } from '../../../../components/i18n';
import { APP_BASE_PATH } from '../../../../relay/environment';

const UNSAFE_FILE_EXTENSIONS = ['.exe', '.pif', '.dll'];

/**
 * Tells whether a file may be malicious: any file of an Artifact, or a binary.
 * Such a file is never opened in the browser: it is downloaded through {@link FileDownloadWarningDialog}.
 */
export const isPotentiallyMaliciousFile = (fileId: string, isArtifact?: boolean) => {
  const lowerFileId = fileId.toLowerCase();
  return !!isArtifact || UNSAFE_FILE_EXTENSIONS.some((extension) => lowerFileId.endsWith(extension));
};

interface FileDownloadWarningDialogProps {
  fileId: string | null | undefined;
  open: boolean;
  onClose: () => void;
}

/**
 * Warns before downloading a file that may be malicious, and offers it as an encrypted archive or as the raw file.
 */
const FileDownloadWarningDialog: FunctionComponent<FileDownloadWarningDialogProps> = ({ fileId, open, onClose }) => {
  const { t_i18n } = useFormatter();
  const download = (kind: 'get' | 'encrypted') => {
    onClose();
    if (fileId) {
      window.location.pathname = `${APP_BASE_PATH}/storage/${kind}/${encodeURIComponent(fileId)}`;
    }
  };
  return (
    <Dialog open={open} onClose={onClose}>
      <DialogContentText>
        {t_i18n('How do you want to download this file?')}
      </DialogContentText>
      <Alert
        severity="warning"
        variant="outlined"
        style={{ position: 'relative', marginTop: 20 }}
      >
        {t_i18n(
          'You are about to download a file related to an Artifact (or a binary). It might be malicious. You can download it as an encrypted archive (password: "infected") in order to protect your workstation and share it safely.',
        )}
      </Alert>
      <DialogActions>
        <Button onClick={onClose}>
          {t_i18n('Cancel')}
        </Button>
        <Button onClick={() => download('get')}>
          {t_i18n('Raw file')}
        </Button>
        <Button onClick={() => download('encrypted')}>
          {t_i18n('Encrypted archive')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default FileDownloadWarningDialog;
