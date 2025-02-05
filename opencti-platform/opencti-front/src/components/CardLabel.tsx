import React, { CSSProperties, FunctionComponent, ReactNode } from 'react';
import { Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';

interface CardLabelProps {
  children: ReactNode,
  action?: ReactNode,
  style?: CSSProperties,
}

const CardLabel: FunctionComponent<CardLabelProps> = ({
  children,
  action,
  style = {},
}) => {
  const theme = useTheme();
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'row',
      alignItems: 'center',
      height: '20px',
      marginBottom: theme.spacing(0.5),
      ...style,
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
