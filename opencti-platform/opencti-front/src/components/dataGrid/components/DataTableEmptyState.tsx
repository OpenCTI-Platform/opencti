import React from 'react';

type DataTableEmptyStateProps = {
  message: string
};

const DataTableEmptyState = ({ message } : DataTableEmptyStateProps) => {
  return (
    <div style={{
      display: 'table',
      height: '100%',
      width: '100%',
      textAlign: 'center',
    }}
    >
      {message}
    </div>
  );
};

export default DataTableEmptyState;
