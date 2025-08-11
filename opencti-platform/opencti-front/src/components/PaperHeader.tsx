import React, { ReactNode } from 'react';
import { Typography } from '@mui/material';

export interface PaperHeaderProps {
  title?: ReactNode
  actions?: ReactNode
}

const PaperHeader = ({ actions, title }: PaperHeaderProps) => {
  if (!title && !actions) return null;

  return (
    <div style={{
      display: 'flex',
      alignItems: 'flex-start',
      height: 19,
    }}
    >
      {title && (
        <Typography
          variant="h4"
          gutterBottom
          sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
        >
          {title}
        </Typography>
      )}
      {actions}
    </div>
  );
};

export default PaperHeader;
