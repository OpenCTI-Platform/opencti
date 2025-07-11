import React, { ReactNode } from 'react';
import { PaperProps as MuiPaperProps, Typography, Paper as MuiPaper } from '@mui/material';

interface PaperProps extends Omit<MuiPaperProps, 'title'> {
  title?: ReactNode
}

const Paper = ({ title, children, ...muiProps }: PaperProps) => {
  return (
    <div>
      {title && (
        <Typography
          variant="h4"
          gutterBottom
          sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
        >
          {title}
        </Typography>
      )}
      <MuiPaper
        variant="outlined"
        className="paper-for-grid"
        sx={{
          marginTop: 1,
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
