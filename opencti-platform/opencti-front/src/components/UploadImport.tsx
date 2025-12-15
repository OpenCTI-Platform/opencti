import React, { useState } from 'react';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import IconButton from '@common/button/IconButton';
import Button from '@common/button/Button';
import { UploadFileOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import ImportFilesDialog from '@components/common/files/import_files/ImportFilesDialog';
import { useFormatter } from './i18n';
import useDraftContext from '../utils/hooks/useDraftContext';
import { useGetCurrentUserAccessRight } from '../utils/authorizedMembers';

interface UploadImportProps {
  color?: 'primary' | 'secondary' | 'success' | 'error' | 'info' | 'warning';
  size?: 'small' | 'default';
  fontSize?: 'small' | 'medium' | 'large';
  variant?: 'text' | 'contained' | 'outlined' | 'icon';
  style?: React.CSSProperties;
  onSuccess?: () => void;
  entityId?: string;
}

const UploadImport = ({
  color = 'primary',
  size = 'default',
  variant = 'icon',
  fontSize = 'medium',
  style,
  onSuccess,
  entityId,
}: UploadImportProps) => {
  const theme = useTheme<Theme>();
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
            color={color}
            size={size}
            aria-haspopup="true"
            onClick={() => setOpenImportFilesDialog(true)}
          >
            <UploadFileOutlined fontSize={fontSize} />
          </IconButton>
        </Tooltip>
      ) : (
        <Button
          onClick={() => setOpenImportFilesDialog(true)}
          color={color}
          size={size}
          // variant={variant}
          aria-label={title}
          title={title}
          sx={style ?? { marginLeft: theme.spacing(1) }}
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
