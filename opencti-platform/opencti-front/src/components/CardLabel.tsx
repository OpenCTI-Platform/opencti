import React, { FunctionComponent, ReactNode } from 'react';
import { Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';

interface CardLabelProps {
  children: ReactNode,
  action?: ReactNode,
}

const CardLabel: FunctionComponent<CardLabelProps> = ({
  children,
  action,
}) => {
  const theme = useTheme();
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'row',
      alignItems: 'center',
      height: '20px',
      marginBottom: theme.spacing(0.5),
    }}
    >
      <Typography variant="h3" sx={{ marginBottom: 0 }}>
        {children}
      </Typography>
      {action}
    </div>
  );
};

export default CardLabel;
