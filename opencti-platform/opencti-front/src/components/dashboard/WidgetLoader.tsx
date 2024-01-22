import CircularProgress from '@mui/material/CircularProgress';
import React from 'react';

const WidgetLoader = () => {
  return (
    <div
      style={{
        height: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <CircularProgress size={40} thickness={2} />
    </div>
  );
};

export default WidgetLoader;
