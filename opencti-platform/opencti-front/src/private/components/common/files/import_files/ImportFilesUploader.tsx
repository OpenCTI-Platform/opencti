import { useTheme } from '@mui/styles';
import React, { useState } from 'react';
import { Box, Button, Collapse, Grid, IconButton, List, ListItem, Typography, TextField } from '@mui/material';
import { TransitionGroup } from 'react-transition-group';
import { CloudUploadOutlined, DeleteOutlined, UploadFileOutlined } from '@mui/icons-material';
import { alpha } from '@mui/material/styles';
import { Field, Formik } from 'formik';
import { FormikHelpers } from 'formik/dist/types';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { isValidStixBundle } from '../../../../../utils/String';
import { now } from '../../../../../utils/Time';

type FileFreeTextType = { content: string };

interface ImportFilesUploaderProps {
  files?: File[];
  onChange: (files: File[]) => void;
}

const ImportFilesUploader = ({ files = [], onChange }: ImportFilesUploaderProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [isDragging, setIsDragging] = useState(false);
  const [isTextView, setIsTextView] = useState(false);

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

  const createFileFreeText = (
    { content }: FileFreeTextType,
    { resetForm }: FormikHelpers<FileFreeTextType>,
  ) => {
    const fileType = isValidStixBundle(content) ? 'json' : 'txt';
    const blob = new Blob([content], { type: `text/${fileType}` });
    const file = new File(
      [blob],
      `${now()}_global.${fileType}`,
      {
        type: fileType === 'json' ? 'application/json' : 'text/plain',
      },
    ) as File;
    onChange([...files, file]);
    setIsTextView(false);
    resetForm();
  };

  return (
    <Grid container>
      <Grid item xs={12}>
        { !isTextView ? (
          <Box
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragging(true);
            }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            sx={{
              height: files.length > 0 ? 150 : 300,
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
            <CloudUploadOutlined color="primary" fontSize="large"/>
            <Typography variant="h3" sx={{ marginBlock: 2 }}>
              {t_i18n('Drag and drop files to import')}
            </Typography>
            <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2 }}>
              <Button variant="contained" component="label" size="small">
                {t_i18n('Browse files')}
                <input type="file" hidden multiple onChange={handleFileChange}/>
              </Button>
              <Button variant="outlined" component="label" size="small" onClick={() => setIsTextView(true)}>
                {t_i18n('Copy/paste mode')}
              </Button>
            </Box>
          </Box>
        ) : (
          <Formik<FileFreeTextType>
            enableReinitialize={true}
            initialValues={{
              content: '',
            }}
            onSubmit={createFileFreeText}
          >
            {({ handleReset, submitForm, isSubmitting, values }) => {
              return (
                <Box sx={{
                  paddingInline: 2,
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'center',
                  alignItems: 'center',
                  gap: theme.spacing(4),
                }}
                >
                  <Field
                    as={TextField}
                    label={t_i18n('Content')}
                    fullWidth
                    multiline
                    autoFocus
                    name="content"
                    rows="10"
                    variant="standard"
                    InputProps={{ sx: { background: theme.palette.background.paper } }}
                    InputLabelProps={{ shrink: true }}
                  />
                  <Box sx={{ display: 'flex', marginLeft: 'auto' }}>
                    <Button
                      disabled={isSubmitting}
                      onClick={() => {
                        handleReset();
                        setIsTextView(false);
                      }}
                    >
                      {t_i18n('Cancel')}
                    </Button>
                    <Button
                      color="secondary"
                      disabled={isSubmitting || values.content.length === 0}
                      onClick={submitForm}
                    >
                      {t_i18n('Create file')}
                    </Button>
                  </Box>
                </Box>);
            }}
          </Formik>
        )}
      </Grid>

      <Grid item xs={12}>
        <List>
          <TransitionGroup>
            {files.length > 0 && (
              <Collapse key="header" >
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
    </Grid>
  );
};

export default ImportFilesUploader;
