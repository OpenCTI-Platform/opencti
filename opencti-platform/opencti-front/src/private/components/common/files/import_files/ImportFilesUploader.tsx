import React, { useState } from 'react';
import { Collapse, Grid, IconButton, List, ListItem } from '@mui/material';
import { TransitionGroup } from 'react-transition-group';
import { DeleteOutlined, UploadFileOutlined } from '@mui/icons-material';
import ImportFilesDropzone from '@components/common/files/import_files/ImportFilesDropzone';
import ImportFilesFreeText from '@components/common/files/import_files/ImportFilesFreeText';
import { useFormatter } from '../../../../../components/i18n';

interface ImportFilesUploaderProps {
  files?: File[];
  onChange: (files: File[]) => void;
}

const ImportFilesUploader = ({ files = [], onChange }: ImportFilesUploaderProps) => {
  const { t_i18n } = useFormatter();
  const [isTextView, setIsTextView] = useState(false);

  const addFiles = (newFiles: File[]) => {
    onChange([...files, ...newFiles]);
  };

  const removeFile = (name: string) => {
    onChange(files.filter((file) => file.name !== name));
  };

  return (
    <Grid container>
      <Grid item xs={12}>
        { !isTextView ? (
          <ImportFilesDropzone
            fullSize={files.length === 0}
            onChange={addFiles}
            openFreeText={() => setIsTextView(true)}
          />
        ) : (
          <ImportFilesFreeText onSumbit={(file) => {
            addFiles([file]);
            setIsTextView(false);
          }}
            onClose={ () => setIsTextView(false) }
          />
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
