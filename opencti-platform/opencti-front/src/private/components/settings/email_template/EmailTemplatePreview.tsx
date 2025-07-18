import React, { CSSProperties } from 'react';
import { Paper } from '@mui/material';
import { useTheme } from '@mui/styles';
import Typography from '@mui/material/Typography';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';

const EmailTemplatePreview = () => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const paperStyle: CSSProperties = {
    padding: theme.spacing(2),
    flex: 1,
    overflow: 'hidden',
  };

  return (
    <div style={{
      height: 'calc(100vh - 280px)',
      display: 'flex',
      gap: theme.spacing(3),
    }}
    >
      <div style={{ flex: 5, display: 'flex', flexDirection: 'column' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t_i18n('Preview')}
        </Typography>
        <Paper style={paperStyle} variant="outlined">
        </Paper>
      </div>
    </div>
  );
};

export default EmailTemplatePreview;
