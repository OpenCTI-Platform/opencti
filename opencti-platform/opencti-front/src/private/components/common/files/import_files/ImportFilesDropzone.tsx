import { alpha } from '@mui/material/styles';
import { CloudUploadOutlined } from '@mui/icons-material';
import { Box, Typography } from '@mui/material';
import React, { useState } from 'react';
import Button from '@common/button/Button';
import { useTheme } from '@mui/styles';
import { useImportFilesContext } from '@components/common/files/import_files/ImportFilesContext';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';

interface ImportFilesDropzoneProps {
  fullSize?: boolean;
  onChange: (files: File[]) => void;
  openFreeText?: (value: boolean) => void;
}

const ImportFilesDropzone = ({
  fullSize = true,
  onChange,
  openFreeText,
}: ImportFilesDropzoneProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [isDragging, setIsDragging] = useState(false);
  const { guessMimeType } = useImportFilesContext();

  const processNewFiles = async (files: FileList) => {
    const newFiles = await Promise.all(Array.from(files).map(async (file) => {
      const guessedType = await guessMimeType(file.name);
      return new File([file], file.name, {
        type: guessedType || file.type,
        lastModified: file.lastModified,
      });
    }));
    onChange(newFiles);
  };

  const handleFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files) {
      await processNewFiles(event.target.files);
    }
  };

  const handleDrop = async (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);
    if (event.dataTransfer.files) {
      await processNewFiles(event.dataTransfer.files);
    }
  };

  return (
    <Box
      onDragOver={(e) => {
        e.preventDefault();
        setIsDragging(true);
      }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      sx={{
        height: fullSize ? 300 : 150,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        background: isDragging ? alpha(theme.palette.primary.light as string, 0.1) : theme.palette.background.paper,
        borderRadius: 4,
        borderColor: isDragging ? theme.palette.primary.main : theme.palette.common.lightGrey,
        borderWidth: isDragging ? '2px' : '1px',
        borderStyle: 'dashed',
        boxSizing: 'border-box',
        padding: isDragging ? '19.5px' : '20px',
        textAlign: 'center',
        marginBottom: 2,
        cursor: 'default',
        transition: 'height 0.2s, background 0.1s, border 0.1s, padding 0.1s',
      }}
    >
      <CloudUploadOutlined color="primary" fontSize="large" />
      <Typography variant="h3" sx={{ marginBlock: 2 }}>
        {t_i18n('Drag and drop files to import')}
      </Typography>
      <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2 }}>
        <Button component="label" size="small">
          {t_i18n('Browse files')}
          <input type="file" hidden multiple onChange={handleFileChange} />
        </Button>
        {openFreeText && (
          <Button variant="secondary" component="label" size="small" onClick={() => openFreeText?.(true)}>
            {t_i18n('Copy/paste mode')}
          </Button>
        )}
      </Box>
    </Box>
  );
};

export default ImportFilesDropzone;
