import Box from '@mui/material/Box';

type DataTableEmptyStateProps = {
  message: string;
};

const DataTableEmptyState = ({ message }: DataTableEmptyStateProps) => {
  return (
    <Box sx={{
      display: 'table',
      height: '100%',
      width: '100%',
      textAlign: 'center',
      color: 'text.disabled',
    }}
    >
      {message}
    </Box>
  );
};

export default DataTableEmptyState;
