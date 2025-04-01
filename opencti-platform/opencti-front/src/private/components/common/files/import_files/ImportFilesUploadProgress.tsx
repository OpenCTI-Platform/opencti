import React from 'react';
import { Box, LinearProgress, List, ListItem, Typography } from '@mui/material';
import { CancelOutlined, CheckCircleOutlined, UploadFileOutlined } from '@mui/icons-material';
import { useImportFilesContext } from '@components/common/files/import_files/ImportFilesContext';

interface ImportFilesUploadProgressProps {
  currentCount: number;
  totalCount: number;
  uploadedFiles: { name: string; status?: 'success' | 'error' }[];
  BulkResult: React.FC<{ variablesToString: (variables: { file: File }) => string }>;
}

const ImportFilesUploadProgress: React.FC<ImportFilesUploadProgressProps> = ({
  currentCount,
  totalCount,
  uploadedFiles,
  BulkResult,
}) => {
  const { uploadStatus } = useImportFilesContext();

  return (
    <div style={{ display: 'flex', height: '100%', justifyContent: 'center', flexDirection: 'column' }}>
      <Box sx={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
        <LinearProgress
          variant="buffer"
          sx={{ flex: 1 }}
          value={(currentCount / totalCount) * 100}
          valueBuffer={((currentCount / totalCount) * 100) + 10}
        />
        <Typography style={{ flexShrink: 0 }}>{`${currentCount}/${totalCount}`}</Typography>
      </Box>
      <List>
        {uploadedFiles.map((file) => (
          <ListItem
            key={file.name}
            divider
            secondaryAction={
              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                {
                  file.status === 'error' ? (
                    <CancelOutlined fontSize="small" color="error" />
                  ) : (
                    <CheckCircleOutlined fontSize="small" color={file.status ?? 'inherit'} />
                  )
                }
              </Box>
            }
          >
            <UploadFileOutlined color="primary" sx={{ marginRight: 2 }} />
            {file.name}
          </ListItem>
        ))}
      </List>
      {uploadStatus === 'success' && <BulkResult variablesToString={(v) => v.file.name} />}
    </div>
  );
};

export default ImportFilesUploadProgress;
