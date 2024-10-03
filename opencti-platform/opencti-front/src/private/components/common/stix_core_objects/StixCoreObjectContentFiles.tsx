import React, { useState } from 'react';
import * as R from 'ramda';
import List from '@mui/material/List';
import ListItemText from '@mui/material/ListItemText';
import Drawer from '@mui/material/Drawer';
import ListItemIcon from '@mui/material/ListItemIcon';
import { FileOutline, FilePdfBox, LanguageHtml5, LanguageMarkdownOutline, NoteTextOutline } from 'mdi-material-ui';
import moment from 'moment';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { AddOutlined, DeleteOutlined } from '@mui/icons-material';
import { Field, Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import ListItemButton from '@mui/material/ListItemButton';
import Typography from '@mui/material/Typography';
import MenuItem from '@mui/material/MenuItem';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import makeStyles from '@mui/styles/makeStyles';
import ObjectMarkingField from '../form/ObjectMarkingField';
import { useFormatter } from '../../../../components/i18n';
import FileUploader from '../files/FileUploader';
import { FileLineDeleteMutation } from '../files/FileLine';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/fields/SelectField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { templateList } from '../../../../utils/outcome_template/engine/__template';
import useOutcomeTemplate from '../../../../utils/outcome_template/engine/templateWidgetEngine';

const useStyles = makeStyles((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 350,
    padding: '10px 0 20px 0',
    position: 'fixed',
    zIndex: 1100,
  },
  toolbar: theme.mixins.toolbar,
}));

export const stixCoreObjectContentFilesUploadStixCoreObjectMutation = graphql`
  mutation StixCoreObjectContentFilesUploadStixCoreObjectMutation(
    $id: ID!
    $file: Upload!
    $fileMarkings: [String]
    $noTriggerImport: Boolean
  ) {
    stixCoreObjectEdit(id: $id) {
      importPush(file: $file, noTriggerImport: $noTriggerImport, fileMarkings: $fileMarkings) {
        id
        name
        uploadStatus
        lastModified
        lastModifiedSinceMin
        metaData {
          mimetype
          list_filters
          messages {
            timestamp
            message
          }
          errors {
            timestamp
            message
          }
        }
        metaData {
          mimetype
        }
      }
    }
  }
`;

const StixCoreObjectContentFiles = ({
  files,
  stixCoreObjectId,
  content,
  handleSelectFile,
  handleSelectContent,
  contentSelected,
  currentFileId,
  onFileChange,
  settingsMessagesBannerHeight,
  exportFiles,
  handleSelectExportFile,
}) => {
  const classes = useStyles();
  const { t_i18n, fld } = useFormatter();
  const { buildOutcomeTemplate } = useOutcomeTemplate();

  const [deleting, setDeleting] = useState<string | null>(null);
  const [displayCreate, setDisplayCreate] = useState(false);
  const [displayCreateOutcomeTemplate, setDisplayCreateOutcomeTemplate] = useState(false);

  const fileValidation = () => Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
  });

  const handleOpenCreate = () => {
    setDisplayCreate(true);
  };

  const handleOpenCreateOutcomeTemplate = () => {
    setDisplayCreateOutcomeTemplate(true);
  };

  const handleCloseCreate = () => {
    setDisplayCreate(false);
  };

  const handleCloseCreateOutcomeTemplate = () => {
    setDisplayCreateOutcomeTemplate(false);
  };

  const submitDelete = (fileName: string, event: MouseEvent) => {
    event.stopPropagation();
    event.preventDefault();
    setDeleting(fileName);
    commitMutation({
      mutation: FileLineDeleteMutation,
      variables: {
        fileName,
      },
      onCompleted: () => {
        setDeleting(null);
        onFileChange(fileName, true);
      },
      updater: undefined,
      onError: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      setSubmitting: undefined,
    });
  };

  const onReset = () => {
    handleCloseCreate();
  };

  const onResetOutcomeTemplate = () => {
    handleCloseCreateOutcomeTemplate();
  };

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    // eslint-disable-next-line prefer-const
    let { name, type } = values;
    if (type === 'text/plain' && !name.endsWith('.txt')) {
      name += '.txt';
    } else if (
      type === 'text/html'
      && !name.endsWith('.html')
    ) {
      name += '.html';
    } else if (
      type === 'text/markdown'
      && !name.endsWith('.md')
    ) {
      name += '.md';
    }
    const blob = new Blob([t_i18n('Write something awesome...')], {
      type,
    });
    const file = new File([blob], name, {
      type,
    });

    const fileMarkings = values.fileMarkings.map(({ value }) => value);

    commitMutation({
      mutation: stixCoreObjectContentFilesUploadStixCoreObjectMutation,
      variables: { file, id: stixCoreObjectId, fileMarkings },
      setSubmitting,
      onCompleted: (result) => {
        setSubmitting(false);
        resetForm();
        handleCloseCreate();
        onFileChange(result.stixCoreObjectEdit.importPush.id);
      },
      updater: undefined,
      onError: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
    });
  };

  const onSubmitOutcomeTemplate = async (values, { setSubmitting, resetForm }) => {
    // eslint-disable-next-line prefer-const
    let { name, type } = values;
    if (
      type === 'text/html'
      && !name.endsWith('.html')
    ) {
      name += '.html';
    }

    // const templateContent = template1.content; // TODO remove hardcoded
    const templateContent = await buildOutcomeTemplate(stixCoreObjectId, templateList);
    console.log('templateContent', templateContent);

    const blob = new Blob([templateContent], {
      type,
    });
    const file = new File([blob], name, {
      type,
    });

    const fileMarkings = values.fileMarkings.map(({ value }) => value);
    const maxMarkings = (values.max_markings ?? []).map(({ value }) => value); // TODO

    commitMutation({
      mutation: stixCoreObjectContentFilesUploadStixCoreObjectMutation,
      variables: { file, id: stixCoreObjectId, fileMarkings },
      setSubmitting,
      onCompleted: (result) => {
        setSubmitting(false);
        resetForm();
        handleCloseCreateOutcomeTemplate();
        onFileChange(result.stixCoreObjectEdit.importPush.id);
      },
      updater: undefined,
      onError: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
    });
  };

  const renderIcon = (mimeType: string) => {
    switch (mimeType) {
      case 'text/plain':
        return <NoteTextOutline />;
      case 'application/pdf':
        return <FilePdfBox />;
      case 'text/markdown':
        return <LanguageMarkdownOutline />;
      case 'text/html':
        return <LanguageHtml5 />;
      default:
        return <FileOutline />;
    }
  };

  const filesList = [...files, ...exportFiles.map((n) => ({ ...n, perspective: 'export' }))]
    .sort((a, b) => b.name.localeCompare(a.name));
  return (
    <Drawer
      variant="permanent"
      anchor="right"
      elevation={1}
      sx={{ zIndex: 1202 }}
      classes={{ paper: classes.drawerPaper }}
    >
      <div className={classes.toolbar} />
      {!R.isNil(content) && (
        <>
          <Typography variant="body2" style={{ margin: '5px 0 0 15px' }}>{t_i18n('Mappable content')}</Typography>
          <List style={{ marginBottom: 30, marginTop: settingsMessagesBannerHeight }}>
            <ListItemButton
              dense={true}
              divider={true}
              selected={contentSelected}
              onClick={handleSelectContent}
            >
              <ListItemIcon>
                <FileOutline fontSize="small" />
              </ListItemIcon>
              <ListItemText
                sx={{
                  '.MuiListItemText-secondary': {
                    whiteSpace: 'pre-line',
                  },
                }}
                primary={t_i18n('Description & Main content')}
                secondary={<div>
                  {t_i18n('Description and content of the entity')}
                </div>}
              />
            </ListItemButton>
          </List>
        </>
      )}
      <div>
        <Typography variant="body2" style={{ margin: '5px 0 0 15px', float: 'left' }}>{t_i18n('Files')}</Typography>
        <div style={{ float: 'right', display: 'flex', margin: '-4px 15px 0 0' }}>
          <FileUploader
            entityId={stixCoreObjectId}
            onUploadSuccess={onFileChange}
            size="small"
            nameInCallback={true}
          />
          <IconButton
            onClick={handleOpenCreate}
            color="primary"
            size="small"
            aria-label={t_i18n('Add a file')}
          >
            <AddOutlined />
          </IconButton>
        </div>
      </div>
      <List style={{ marginBottom: 30 }}>
        {filesList.map((file) => {
          return (
            <Tooltip key={file.id} title={`${file.name} (${file.metaData.mimetype})`}>
              <ListItemButton
                dense={true}
                divider={true}
                selected={file.id === currentFileId}
                onClick={() => (file.perspective === 'export' ? handleSelectExportFile(file.id) : handleSelectFile(file.id))}
                disabled={deleting === file.id}
              >
                <ListItemIcon>
                  {renderIcon(file.metaData.mimetype)}
                </ListItemIcon>
                <ListItemText
                  sx={{
                    '.MuiListItemText-primary': {
                      overflowX: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      marginRight: '20px',
                    },
                  }}
                  primary={file.name}
                  secondary={fld(R.propOr(moment(), 'lastModified', file))}
                />
                <ListItemSecondaryAction>
                  <IconButton onClick={(event) => submitDelete(file.id, event)} size="small">
                    <DeleteOutlined color="primary" fontSize="small"/>
                  </IconButton>
                </ListItemSecondaryAction>
              </ListItemButton>
            </Tooltip>
          );
        })}
      </List>
      <div>
        <Typography variant="body2" style={{ margin: '5px 0 0 15px', float: 'left' }}>{t_i18n('Outcomes templates')}</Typography>
        <div style={{ float: 'right', display: 'flex', margin: '-4px 15px 0 0' }}>
          <Tooltip title={t_i18n('Create an outcome based on a template')}>
            <IconButton
              onClick={handleOpenCreateOutcomeTemplate}
              color="primary"
              size="small"
              aria-label={t_i18n('Create an outcome based on a template')}
            >
              <AddOutlined />
            </IconButton>
          </Tooltip>
        </div>
      </div>
      <Formik
        enableReinitialize={true}
        initialValues={{ name: '', type: 'text/html', fileMarkings: [] }}
        validationSchema={fileValidation}
        onSubmit={onSubmit}
        onReset={onReset}
      >
        {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
          <Form>
            <Dialog
              PaperProps={{ elevation: 1 }}
              open={displayCreate}
              onClose={handleCloseCreate}
              fullWidth={true}
            >
              <DialogTitle>{t_i18n('Create a file')}</DialogTitle>
              <DialogContent>
                <Field
                  component={TextField}
                  variant="standard"
                  name="name"
                  label={t_i18n('Name')}
                  fullWidth={true}
                />
                <Field
                  component={SelectField}
                  variant="standard"
                  name="type"
                  label={t_i18n('Type')}
                  fullWidth={true}
                  containerstyle={fieldSpacingContainerStyle}
                >
                  <MenuItem value="text/html">{t_i18n('HTML')}</MenuItem>
                  <MenuItem value="text/markdown">{t_i18n('Markdown')}</MenuItem>
                  <MenuItem value="text/plain">{t_i18n('Text')}</MenuItem>
                </Field>
                <ObjectMarkingField
                  label={t_i18n('File marking definition levels')}
                  name="fileMarkings"
                  style={fieldSpacingContainerStyle}
                  onChange={() => {}}
                  setFieldValue={setFieldValue}
                />
              </DialogContent>
              <DialogActions>
                <Button onClick={handleReset} disabled={isSubmitting}>
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                >
                  {t_i18n('Create')}
                </Button>
              </DialogActions>
            </Dialog>
          </Form>
        )}
      </Formik>
      <Formik
        enableReinitialize={true}
        initialValues={{
          name: '',
          type: 'text/html',
          fileMarkings: [],
          max_markings: [],
        }}
        validationSchema={fileValidation}
        onSubmit={onSubmitOutcomeTemplate}
        onReset={onResetOutcomeTemplate}
      >
        {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
          <Form>
            <Dialog
              PaperProps={{ elevation: 1 }}
              open={displayCreateOutcomeTemplate}
              onClose={handleCloseCreateOutcomeTemplate}
              fullWidth={true}
            >
              <DialogTitle>{t_i18n('Create an outcome based on a template')}</DialogTitle>
              <DialogContent>
                <Field
                  component={TextField}
                  variant="standard"
                  name="name"
                  label={t_i18n('Name')}
                  fullWidth={true}
                />
                <Field
                  component={SelectField}
                  variant="standard"
                  name="type"
                  label={t_i18n('Type')}
                  fullWidth={true}
                  containerstyle={fieldSpacingContainerStyle}
                >
                  <MenuItem value="text/html">{t_i18n('HTML')}</MenuItem>
                </Field>
                <ObjectMarkingField
                  label={t_i18n('File marking definition levels')}
                  name="fileMarkings"
                  style={fieldSpacingContainerStyle}
                  onChange={() => {}}
                  setFieldValue={setFieldValue}
                />
                <ObjectMarkingField
                  name='max_markings'
                  label={t_i18n('Max content level markings')}
                  helpertext={t_i18n('To prevent people seeing all the data, select a marking definition to restrict the data included in the outcome file.')}
                  style={fieldSpacingContainerStyle}
                  onChange={() => {}}
                  setFieldValue={setFieldValue}
                  limitToMaxSharing
                />
              </DialogContent>
              <DialogActions>
                <Button onClick={handleReset} disabled={isSubmitting}>
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                >
                  {t_i18n('Create')}
                </Button>
              </DialogActions>
            </Dialog>
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

export default StixCoreObjectContentFiles;
