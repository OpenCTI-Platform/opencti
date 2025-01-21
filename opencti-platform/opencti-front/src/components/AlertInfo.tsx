import Alert from '@mui/material/Alert';
import Typography from '@mui/material/Typography';
import React, { ReactNode } from 'react';
import { useTheme } from '@mui/styles';
import { Theme } from 'src/components/Theme';

type AlertInfoProps = {
  content: string | ReactNode;
};

const AlertInfo = ({ content }: AlertInfoProps) => {
  const theme = useTheme<Theme>();

  return (
    <div style={{ width: '100%', margin: `${theme.spacing(2)} 0` }}>
      <Alert
        severity="info"
        variant="outlined"
        style={{ padding: '0px 10px' }}
      >
        <Typography>
          {content}
        </Typography>
      </Alert>
    </div>
  );
};

export default AlertInfo;
