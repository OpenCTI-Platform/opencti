import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
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
import ObjectMarkingField from '../form/ObjectMarkingField';
import inject18n from '../../../../components/i18n';
import FileUploader from '../files/FileUploader';
import { FileLineDeleteMutation } from '../files/FileLine';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import withHooksSettingsMessagesBannerHeight from '../../settings/settings_messages/withHooksSettingsMessagesBannerHeight';
import SelectField from '../../../../components/fields/SelectField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 350,
    padding: '10px 0 20px 0',
    position: 'fixed',
    zIndex: 1100,
  },
  toolbar: theme.mixins.toolbar,
  subHeader: {
    margin: '5px 0 0 20px',
    width: '100%',
  },
});

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

const fileValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
});

class StixCoreObjectContentFiles extends Component {
  constructor(props) {
    super(props);
    this.state = {
      deleting: null,
      displayCreate: false,
    };
  }

  handleOpenCreate() {
    this.setState({ displayCreate: true });
  }

  handleCloseCreate() {
    this.setState({ displayCreate: false });
  }

  renderNoFiles() {
    const { t, classes } = this.props;
    return (
      <ListItem dense={true} classes={{ root: classes.item }}>
        <i>{t('No files in this category.')}</i>
      </ListItem>
    );
  }

  submitDelete(fileName, event) {
    event.stopPropagation();
    event.preventDefault();
    this.setState({ deleting: fileName });
    commitMutation({
      mutation: FileLineDeleteMutation,
      variables: {
        fileName,
      },
      onCompleted: () => {
        this.setState({ deleting: null });
        this.props.onFileChange(fileName, true);
      },
    });
  }

  onReset() {
    this.handleCloseCreate();
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const { t, stixCoreObjectId } = this.props;
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
    const blob = new Blob([t('Write something awesome...')], {
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
        this.handleCloseCreate();
        this.props.onFileChange(result.stixCoreObjectEdit.importPush.id);
      },
    });
  }

  // eslint-disable-next-line class-methods-use-this
  renderIcon(mimeType) {
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
  }

  render() {
    const {
      classes,
      t,
      files,
      stixCoreObjectId,
      content,
      handleSelectFile,
      handleSelectContent,
      contentSelected,
      fld,
      currentFileId,
      onFileChange,
      settingsMessagesBannerHeight,
      exportFiles,
      handleSelectExportFile,
    } = this.props;
    const { deleting, displayCreate } = this.state;
    const filesList = [...files, ...exportFiles.map((n) => ({ ...n, perspective: 'export' }))].sort((a, b) => b.name.localeCompare(a.name));
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
          <Typography variant="body2" style={{ margin: '5px 0 0 15px' }}>{t('Mappable content')}</Typography>
          <List style={{ marginBottom: 30, marginTop: settingsMessagesBannerHeight }}>
            <ListItemButton
              dense={true}
              divider={true}
              selected={contentSelected}
              onClick={handleSelectContent.bind(this)}
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
                primary={t('Description & Main content')}
                secondary={<div>
                  {t('Description and content of the entity')}
                </div>}
              />
            </ListItemButton>
          </List>
        </>
        )}
        <div>
          <Typography variant="body2" style={{ margin: '5px 0 0 15px', float: 'left' }}>{t('Files')}</Typography>
          <div style={{ float: 'right', display: 'flex', margin: '-4px 15px 0 0' }}>
            <FileUploader
              entityId={stixCoreObjectId}
              onUploadSuccess={onFileChange.bind(this)}
              size="small"
              nameInCallback={true}
            />
            <IconButton
              onClick={this.handleOpenCreate.bind(this)}
              color="primary"
              size="small"
              aria-label={t('Add a file')}
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
                    {this.renderIcon(file.metaData.mimetype)}
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
                    <IconButton onClick={this.submitDelete.bind(this, file.id)} size="small">
                      <DeleteOutlined color="primary" fontSize="small"/>
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItemButton>
              </Tooltip>
            );
          })}
        </List>
        <Formik
          enableReinitialize={true}
          initialValues={{ name: '', type: 'text/html', fileMarkings: [] }}
          validationSchema={fileValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.onReset.bind(this)}
        >
          {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
            <Form>
              <Dialog
                PaperProps={{ elevation: 1 }}
                open={displayCreate}
                onClose={this.handleCloseCreate.bind(this)}
                fullWidth={true}
              >
                <DialogTitle>{t('Create a file')}</DialogTitle>
                <DialogContent>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                  />
                  <Field
                    component={SelectField}
                    variant="standard"
                    name="type"
                    label={t('Type')}
                    fullWidth={true}
                    containerstyle={fieldSpacingContainerStyle}
                  >
                    <MenuItem value="text/html">{t('HTML')}</MenuItem>
                    <MenuItem value="text/markdown">{t('Markdown')}</MenuItem>
                    <MenuItem value="text/plain">{t('Text')}</MenuItem>
                  </Field>
                  <ObjectMarkingField
                    label={t('File marking definition levels')}
                    name="fileMarkings"
                    style={fieldSpacingContainerStyle}
                    onChange={() => {}}
                    setFieldValue={setFieldValue}
                  />
                </DialogContent>
                <DialogActions>
                  <Button onClick={handleReset} disabled={isSubmitting}>
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                  >
                    {t('Create')}
                  </Button>
                </DialogActions>
              </Dialog>
            </Form>
          )}
        </Formik>
      </Drawer>
    );
  }
}

StixCoreObjectContentFiles.propTypes = {
  stixCoreObjectId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  files: PropTypes.array,
  currentFileId: PropTypes.string,
  handleSelectFile: PropTypes.func,
  onFileChange: PropTypes.func,
  exportFiles: PropTypes.array,
  handleSelectExportFile: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles),
  withHooksSettingsMessagesBannerHeight,
)(StixCoreObjectContentFiles);
