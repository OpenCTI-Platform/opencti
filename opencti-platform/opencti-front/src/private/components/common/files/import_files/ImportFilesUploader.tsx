import { useTheme } from '@mui/styles';
import React, { useState } from 'react';
import { Box, Button, Collapse, Grid, IconButton, List, ListItem, Typography } from '@mui/material';
import { TransitionGroup } from 'react-transition-group';
import { CloudUploadOutlined, DeleteOutlined, UploadFileOutlined } from '@mui/icons-material';
import { alpha } from '@mui/material/styles';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';

interface ImportFilesUploaderProps {
  files?: File[];
  onChange: (files: File[]) => void;
}

const ImportFilesUploader = ({ files = [], onChange }: ImportFilesUploaderProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [isDragging, setIsDragging] = useState(false);

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files) {
      const newFiles = Array.from(event.target.files).map((file) => Object.assign(file, { preview: URL.createObjectURL(file) }));
      onChange([...files, ...newFiles]);
    }
  };

  const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);
    if (event.dataTransfer.files) {
      const newFiles = Array.from(event.dataTransfer.files).map((file) => Object.assign(file, { preview: URL.createObjectURL(file) }));
      onChange([...files, ...newFiles]);
    }
  };

  const removeFile = (name: string) => {
    onChange(files.filter((file) => file.name !== name));
  };

  return (
    <Grid container>
      <Grid item xs={12}>
        <List>
          <TransitionGroup>
            {files.length > 0 && (
              <Collapse key="header">
                <ListItem divider sx={{ paddingLeft: 7 }}>
                  {t_i18n('File')}
                </ListItem>
              </Collapse>
            )}

            {files.map((file) => (
              <Collapse key={file.name}>
                <ListItem
                  divider
                  secondaryAction={
                    <IconButton edge="end" onClick={() => removeFile(file.name)} color="primary">
                      <DeleteOutlined />
                    </IconButton>
                  }
                >
                  <UploadFileOutlined color="primary" sx={{ marginRight: 2 }} />
                  {file.name}
                </ListItem>
              </Collapse>
            ))}
          </TransitionGroup>
        </List>
      </Grid>

      <Grid item xs={12}>
        <Box
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          sx={{
            height: 300,
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
            transition: 'background 0.1s, border 0.1s, padding 0.1s',
          }}
        >
          <CloudUploadOutlined color="primary" fontSize="large" />
          <Typography variant="h3" sx={{ marginBlock: 2 }}>
            {t_i18n('Drag and drop files to import')}
          </Typography>
          <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2 }}>
            <Button variant="contained" component="label" size="small">
              {t_i18n('Browse files')}
              <input type="file" hidden multiple onChange={handleFileChange} />
            </Button>
            <Button variant="outlined" component="label" size="small">
              {t_i18n('Paste from clipboard')}
              {/* TODO paste from clipboard */}
            </Button>
          </Box>
        </Box>
      </Grid>
    </Grid>
  );
};

export default ImportFilesUploader;
