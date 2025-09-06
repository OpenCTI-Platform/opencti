import React from 'react';
import { PaperProps as MuiPaperProps, Paper as MuiPaper } from '@mui/material';
import PaperHeader, { PaperHeaderProps } from './PaperHeader';

interface PaperProps extends PaperHeaderProps, Omit<MuiPaperProps, 'title'> {}

const Paper = ({ title, actions, children, ...muiProps }: PaperProps) => {
  return (
    <div>
      <PaperHeader title={title} actions={actions} />
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
