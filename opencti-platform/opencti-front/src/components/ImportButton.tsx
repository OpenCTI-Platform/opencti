import { Button, ButtonProps } from '@mui/material';
import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import IconButton from '@mui/material/IconButton';
import { CloudUploadOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { useFormatter } from './i18n';

interface ImportButtonProps {
  onClick: ButtonProps['onClick']
  color?: 'primary' | 'inherit' | 'secondary' | 'success' | 'error' | 'info' | 'warning';
  size?: 'small' | 'medium' | 'large';
  variant?: 'text' | 'contained' | 'outlined' | 'icon';
  style?: React.CSSProperties;
}

const ImportButton: FunctionComponent<ImportButtonProps> = ({
  onClick,
  color = 'primary',
  size = 'small',
  variant = 'contained',
  style,
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const title = t_i18n('Import files');
  return variant === 'icon' ? (
    <Tooltip title={title} aria-label={title}>
      <IconButton
        color={color}
        size={size}
        aria-haspopup="true"
        onClick={onClick}
      >
        <CloudUploadOutlined/>
      </IconButton>
    </Tooltip>
  ) : (
    <Button
      onClick={onClick}
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
  );
};

export default ImportButton;
