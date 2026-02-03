import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import ImportFilesDialog from '@components/common/files/import_files/ImportFilesDialog';
import { FileUploadOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import React, { useState } from 'react';
import { useGetCurrentUserAccessRight } from '../utils/authorizedMembers';
import useDraftContext from '../utils/hooks/useDraftContext';
import { useFormatter } from './i18n';

interface UploadImportProps {
  size?: 'small' | 'default';
  fontSize?: 'small' | 'medium' | 'large';
  variant?: 'text' | 'contained' | 'outlined' | 'icon';
  style?: React.CSSProperties;
  onSuccess?: () => void;
  entityId?: string;
}

const UploadImport = ({
  size = 'default',
  variant = 'icon',
  fontSize = 'medium',
  onSuccess,
  entityId,
}: UploadImportProps) => {
  const { t_i18n } = useFormatter();
  const title = t_i18n('Import data');
  const [openImportFilesDialog, setOpenImportFilesDialog] = useState(false);
  // Remove import button in Draft context without the minimal right access "canEdit"
  const draftContext = useDraftContext();
  const currentAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  const canDisplayButton = !draftContext || currentAccessRight.canEdit;

  return canDisplayButton && (
    <>
      {openImportFilesDialog && (
        <ImportFilesDialog
          open={openImportFilesDialog}
          handleClose={() => {
            onSuccess?.();
            setOpenImportFilesDialog(false);
          }}
          entityId={entityId}
        />
      )}
      {variant === 'icon' ? (
        <Tooltip title={title} aria-label={title}>
          <IconButton
            size={size}
            aria-haspopup="true"
            onClick={() => setOpenImportFilesDialog(true)}
          >
            <FileUploadOutlined fontSize={fontSize} />
          </IconButton>
        </Tooltip>
      ) : (
        <Button
          onClick={() => setOpenImportFilesDialog(true)}
          size={size}
          aria-label={title}
          title={title}
        >
          <div style={{ display: 'flex' }}>
            {title}
          </div>
        </Button>
      )}
    </>
  );
};

export default UploadImport;
