import React, { useState } from 'react';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import { UploadFileOutlined } from '@mui/icons-material';
import ImportFilesDialog from '@private/components/common/files/import_files/ImportFilesDialog';
import { useFormatter } from './i18n';
import { Button, IconButton, Tooltip } from '@components';
interface UploadImportProps {
  color?: 'primary' | 'inherit' | 'secondary' | 'success' | 'error' | 'info' | 'warning';
  size?: 'small' | 'medium' | 'large';
  fontSize?: 'small' | 'medium' | 'large';
  variant?: 'text' | 'contained' | 'outlined' | 'icon';
  style?: React.CSSProperties;
  onSuccess?: () => void;
  entityId?: string;
}

const UploadImport = ({
  color = 'primary',
  size = 'medium',
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

  return (
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
            <UploadFileOutlined fontSize={fontSize}/>
          </IconButton>
        </Tooltip>
      ) : (
        <Button
          onClick={() => setOpenImportFilesDialog(true)}
          color={color}
          size={size}
          variant={variant}
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
