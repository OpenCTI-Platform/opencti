import React, { ReactNode } from 'react';
import { PaperProps as MuiPaperProps, Typography, Paper as MuiPaper } from '@mui/material';

interface PaperProps extends Omit<MuiPaperProps, 'title'> {
  title?: ReactNode
  actions?: ReactNode
}

const Paper = ({ title, actions, children, ...muiProps }: PaperProps) => {
  return (
    <div>
      {(title || actions) && (
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
      )}
      <MuiPaper
        variant="outlined"
        className="paper-for-grid"
        sx={{
          marginTop: title || actions ? 1 : 0,
          padding: 2,
          borderRadius: 1,
          position: 'relative',
        }}
        {...muiProps}
      >
        {children}
      </MuiPaper>
    </div>
  );
};

export default Paper;
