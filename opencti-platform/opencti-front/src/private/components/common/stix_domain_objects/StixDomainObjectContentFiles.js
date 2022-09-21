import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Drawer from '@mui/material/Drawer';
import ListSubheader from '@mui/material/ListSubheader';
import ListItemIcon from '@mui/material/ListItemIcon';
import {
  FilePdfBox,
  LanguageHtml5,
  NoteTextOutline,
  FileOutline,
  LanguageMarkdownOutline,
} from 'mdi-material-ui';
import moment from 'moment';
import IconButton from '@mui/material/IconButton';
import { DeleteOutlined, AddOutlined } from '@mui/icons-material';
import { Field, Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import Divider from '@mui/material/Divider';
import inject18n from '../../../../components/i18n';
import FileUploader from '../files/FileUploader';
import { FileLineDeleteMutation } from '../files/FileLine';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 350,
    padding: '10px 0 20px 0',
    position: 'fixed',
    zIndex: 1100,
  },
  drawerPaperExports: {
    minHeight: '100vh',
    width: 250,
    right: 310,
    padding: '0 0 20px 0',
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.easeOut,
      duration: theme.transitions.duration.leavingScreen,
    }),
  },
  listIcon: {
    marginRight: 0,
  },
  itemField: {
    padding: '0 15px 0 15px',
  },
  toolbar: theme.mixins.toolbar,
});

export const stixDomainObjectContentFilesUploadStixDomainObjectMutation = graphql`
  mutation StixDomainObjectContentFilesUploadStixDomainObjectMutation(
    $id: ID!
    $file: Upload!
  ) {
    stixDomainObjectEdit(id: $id) {
      importPush(file: $file, noTriggerImport: true) {
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

class StixDomainObjectContentFiles extends Component {
  constructor(props) {
    super(props);
    this.state = {
      deleting: null,
      displayCreate: false,
      selectedType: null,
    };
  }

  handleOpenCreate(selectedType) {
    this.setState({ displayCreate: true, selectedType });
  }

  handleCloseCreate() {
    this.setState({ displayCreate: false, selectedType: null });
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
        this.props.onFileChange(fileName);
      },
    });
  }

  onReset() {
    this.handleCloseCreate();
  }

  prepareSaveFile() {
    const fragment = this.state.currentFile.id.split('/');
    const currentName = R.last(fragment);
    const currentId = fragment[fragment.length - 2];
    const currentType = fragment[fragment.length - 3];
    const isExternalReference = currentType === 'External-Reference';
    const content = this.state.currentContent;
    const blob = new Blob([content], {
      type: this.state.currentFile.metaData.mimetype,
    });
    const file = new File([blob], currentName, {
      type: this.state.currentFile.metaData.mimetype,
    });
    return { currentId, isExternalReference, file };
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const { t, stixDomainObjectId } = this.props;
    let { name } = values;
    if (this.state.selectedType === 'text/plain' && !name.endsWith('.txt')) {
      name += '.txt';
    } else if (
      this.state.selectedType === 'text/html'
      && !name.endsWith('.html')
    ) {
      name += '.html';
    } else if (
      this.state.selectedType === 'text/markdown'
      && !name.endsWith('.md')
    ) {
      name += '.md';
    }
    const blob = new Blob([t('Write something awesome...')], {
      type: this.state.selectedType,
    });
    const file = new File([blob], name, {
      type: this.state.selectedType,
    });
    commitMutation({
      mutation: stixDomainObjectContentFilesUploadStixDomainObjectMutation,
      variables: { file, id: stixDomainObjectId },
      setSubmitting,
      onCompleted: (result) => {
        setSubmitting(false);
        resetForm();
        this.handleCloseCreate();
        this.props.onFileChange(result.stixDomainObjectEdit.importPush.id);
      },
    });
  }

  render() {
    const {
      classes,
      t,
      files,
      stixDomainObjectId,
      handleSelectFile,
      fld,
      currentFileId,
      onFileChange,
    } = this.props;
    const { deleting, displayCreate } = this.state;
    const textFiles = files.filter((n) => n.metaData.mimetype === 'text/plain');
    const htmlFiles = files.filter((n) => n.metaData.mimetype === 'text/html');
    const markdownFiles = files.filter(
      (n) => n.metaData.mimetype === 'text/markdown',
    );
    const pdfFiles = files.filter(
      (n) => n.metaData.mimetype === 'application/pdf',
    );
    return (
      <Drawer
        variant="permanent"
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
      >
        <div className={classes.toolbar} />
        <List
          style={{ marginBottom: 30 }}
          subheader={
            <ListSubheader component="div">
              <div style={{ float: 'left', margin: '5px 5px 0 0' }}>
                <FilePdfBox />
              </div>
              <div style={{ float: 'left' }}>{t('PDF files')}</div>
              <div style={{ float: 'right' }}>
                <FileUploader
                  entityId={stixDomainObjectId}
                  onUploadSuccess={onFileChange.bind(this)}
                  accept="application/pdf"
                  size="small"
                  nameInCallback={true}
                />
              </div>
            </ListSubheader>
          }
        >
          {pdfFiles.length > 0
            ? pdfFiles.map((file) => (
                <ListItem
                  key={file.id}
                  dense={true}
                  button={true}
                  divider={true}
                  selected={file.id === currentFileId}
                  onClick={handleSelectFile.bind(this, file.id)}
                  disabled={deleting === file.id}
                  secondaryAction={
                    <IconButton onClick={this.submitDelete.bind(this, file.id)}>
                      <DeleteOutlined />
                    </IconButton>
                  }
                >
                  <ListItemIcon>
                    <FileOutline color="primary" />
                  </ListItemIcon>
                  <ListItemText
                    primary={file.name}
                    secondary={fld(R.propOr(moment(), 'lastModified', file))}
                  />
                </ListItem>
            ))
            : this.renderNoFiles()}
        </List>
        <Divider />
        <List
          style={{ marginBottom: 30 }}
          subheader={
            <ListSubheader component="div">
              <div style={{ float: 'left', margin: '5px 5px 0 0' }}>
                <NoteTextOutline />
              </div>
              <div style={{ float: 'left' }}>{t('Text files')}</div>
              <div style={{ float: 'right' }}>
                <FileUploader
                  entityId={stixDomainObjectId}
                  onUploadSuccess={onFileChange.bind(this)}
                  accept="text/plain"
                  size="small"
                  nameInCallback={true}
                />
                <div style={{ float: 'right' }}>
                  <IconButton
                    onClick={this.handleOpenCreate.bind(this, 'text/plain')}
                    color="secondary"
                  >
                    <AddOutlined />
                  </IconButton>
                </div>
              </div>
            </ListSubheader>
          }
        >
          {textFiles.length > 0
            ? textFiles.map((file) => (
                <ListItem
                  key={file.id}
                  dense={true}
                  divider={true}
                  button={true}
                  selected={file.id === currentFileId}
                  onClick={handleSelectFile.bind(this, file.id)}
                  classes={{ root: classes.item }}
                  disabled={deleting === file.id}
                  secondaryAction={
                    <IconButton onClick={this.submitDelete.bind(this, file.id)}>
                      <DeleteOutlined />
                    </IconButton>
                  }
                >
                  <ListItemIcon>
                    <FileOutline color="primary" />
                  </ListItemIcon>
                  <ListItemText
                    primary={file.name}
                    secondary={fld(R.propOr(moment(), 'lastModified', file))}
                  />
                </ListItem>
            ))
            : this.renderNoFiles()}
        </List>
        <Divider />
        <List
          style={{ marginBottom: 30 }}
          subheader={
            <ListSubheader component="div">
              <div style={{ float: 'left', margin: '5px 5px 0 0' }}>
                <LanguageHtml5 />
              </div>
              <div style={{ float: 'left' }}>{t('HTML files')}</div>
              <div style={{ float: 'right' }}>
                <FileUploader
                  entityId={stixDomainObjectId}
                  onUploadSuccess={onFileChange.bind(this)}
                  accept="text/html"
                  size="small"
                  nameInCallback={true}
                />
                <div style={{ float: 'right' }}>
                  <IconButton
                    onClick={this.handleOpenCreate.bind(this, 'text/html')}
                    color="secondary"
                  >
                    <AddOutlined />
                  </IconButton>
                </div>
              </div>
            </ListSubheader>
          }
        >
          {htmlFiles.length > 0
            ? htmlFiles.map((file) => (
                <ListItem
                  key={file.id}
                  dense={true}
                  button={true}
                  divider={true}
                  selected={file.id === currentFileId}
                  onClick={handleSelectFile.bind(this, file.id)}
                  classes={{ root: classes.item }}
                  disabled={deleting === file.id}
                  secondaryAction={
                    <IconButton onClick={this.submitDelete.bind(this, file.id)}>
                      <DeleteOutlined />
                    </IconButton>
                  }
                >
                  <ListItemIcon>
                    <FileOutline color="primary" />
                  </ListItemIcon>
                  <ListItemText
                    primary={file.name}
                    secondary={fld(R.propOr(moment(), 'lastModified', file))}
                  />
                </ListItem>
            ))
            : this.renderNoFiles()}
        </List>
        <Divider />
        <List
          style={{ marginBottom: 30 }}
          subheader={
            <ListSubheader component="div">
              <div style={{ float: 'left', margin: '5px 5px 0 0' }}>
                <LanguageMarkdownOutline />
              </div>
              <div style={{ float: 'left' }}>{t('Markdown files')}</div>
              <div style={{ float: 'right' }}>
                <FileUploader
                  entityId={stixDomainObjectId}
                  onUploadSuccess={onFileChange.bind(this)}
                  accept="text/markdown"
                  size="small"
                  nameInCallback={true}
                />
                <div style={{ float: 'right' }}>
                  <IconButton
                    onClick={this.handleOpenCreate.bind(this, 'text/markdown')}
                    color="secondary"
                  >
                    <AddOutlined />
                  </IconButton>
                </div>
              </div>
            </ListSubheader>
          }
        >
          {markdownFiles.length > 0
            ? markdownFiles.map((file) => (
                <ListItem
                  key={file.id}
                  dense={true}
                  button={true}
                  divider={true}
                  selected={file.id === currentFileId}
                  onClick={handleSelectFile.bind(this, file.id)}
                  classes={{ root: classes.item }}
                  disabled={deleting === file.id}
                  secondaryAction={
                    <IconButton onClick={this.submitDelete.bind(this, file.id)}>
                      <DeleteOutlined />
                    </IconButton>
                  }
                >
                  <ListItemIcon>
                    <FileOutline color="primary" />
                  </ListItemIcon>
                  <ListItemText
                    primary={file.name}
                    secondary={fld(R.propOr(moment(), 'lastModified', file))}
                  />
                </ListItem>
            ))
            : this.renderNoFiles()}
        </List>
        <Formik
          enableReinitialize={true}
          initialValues={{ name: '' }}
          validationSchema={fileValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.onReset.bind(this)}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
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

StixDomainObjectContentFiles.propTypes = {
  stixDomainObjectId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  files: PropTypes.array,
  currentFileId: PropTypes.string,
  handleSelectFile: PropTypes.func,
  onFileChange: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectContentFiles);
