import React, { useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, Stepper, Step, StepButton, List, ListItem, IconButton, Grid, Collapse, Typography, Box } from '@mui/material';
import { useTheme } from '@mui/styles';
import { CloudUploadOutlined, DeleteOutlined, UploadFileOutlined } from '@mui/icons-material';
import { alpha } from '@mui/material/styles';
import { Formik } from 'formik';
import { TransitionGroup } from 'react-transition-group';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import AssociatedEntityField, { AssociatedEntityOption } from '@components/common/form/AssociatedEntityField';
import { Option } from '@components/common/form/ReferenceField';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';
import type { Theme } from '../../../../components/Theme';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

interface ImportFilesDialogProps {
  open: boolean;
  handleClose: () => void;
}

const ImportFilesUploader = ({ files = [], onChange }: { files?: File[], onChange: (files: File[]) => void }) => {
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

const ImportFilesConfigurations = () => {
  return (<Box>CONFIG</Box>);
};

const ImportFilesOptions = ({ setFieldValue, entityId }: { setFieldValue: (name: string, values: Option[] | AssociatedEntityOption) => void; entityId?: string }) => {
  const { t_i18n } = useFormatter();
  return (
    <Box sx={{
      display: 'flex',
      flexDirection: 'column',
      gap: 2,
      width: '50%',
    }}
    >
      <ObjectMarkingField
        name="fileMarkings"
        label={t_i18n('File marking definition levels')}
        style={fieldSpacingContainerStyle}
        setFieldValue={setFieldValue}
        required={false}
      />
      {!entityId
      && (
        <div style={{ paddingTop: '10px' }}>
          <AssociatedEntityField
            label={t_i18n('Associated entity')}
            name="associatedEntity"
            onChange={setFieldValue}
          />
        </div>
      )}
    </Box>
  );
};

type SubmittedFormValues = {
  fileMarkings: Option[];
  associatedEntity: AssociatedEntityOption;
};

const ImportFilesDialog = ({ open, handleClose }: ImportFilesDialogProps) => {
  const { t_i18n } = useFormatter();

  const [activeStep, setActiveStep] = useState(0);
  const [files, setFiles] = useState<File[]>([]);

  const steps = ['Select files', 'Specific files configurations', 'Import options'];

  const onCancel = () => {
    handleClose();
    setActiveStep(0);
    setFiles([]);
  };

  const handleSubmit = (values: SubmittedFormValues) => {
    console.log({ files, values });
    handleClose();
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={{
        fileMarkings: [],
        associatedEntity: { label: '', value: '', type: '' },
      }}
      onSubmit={handleSubmit}
    >
      {({ resetForm, submitForm, setFieldValue }) => (
        <Dialog
          open={open}
          TransitionComponent={Transition}
          fullWidth
          maxWidth={false}
          PaperProps={{
            elevation: 1,
            style: {
              height: '100vh',
            },
          }}
        >
          <DialogTitle>
            <Typography variant="h5">{t_i18n('Import files')}</Typography>
          </DialogTitle>
          <DialogContent sx={{ paddingInline: 20, marginBlock: 10 }}>
            <Stepper nonLinear activeStep={activeStep} sx={{ marginInline: 10 }}>
              {steps.map((label, index) => (
                <Step key={label}>
                  <StepButton color="inherit" onClick={() => setActiveStep(index)}>
                    {label}
                  </StepButton>
                </Step>
              ))}
            </Stepper>
            <Box sx={{ paddingBlock: 10 }}>
              {activeStep === 0 && <ImportFilesUploader files={files} onChange={(newFiles) => setFiles(newFiles)} />}
              {activeStep === 1 && <ImportFilesConfigurations />}
              {activeStep === 2 && <ImportFilesOptions setFieldValue={setFieldValue}/>}
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => {
              resetForm();
              onCancel();
            }}
            >
              {t_i18n('Cancel')}
            </Button>
            {activeStep !== steps.length - 1 ? (
              <Button onClick={() => setActiveStep(activeStep + 1)} color="secondary">
                {t_i18n('Next')}
              </Button>
            ) : (
              <Button onClick={submitForm} color="secondary">
                {t_i18n('Submit')}
              </Button>
            )}
          </DialogActions>
        </Dialog>
      )}
    </Formik>
  );
};

export default ImportFilesDialog;
