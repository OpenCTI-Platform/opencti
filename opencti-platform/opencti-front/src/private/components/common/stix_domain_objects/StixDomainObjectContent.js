import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import Axios from 'axios';
import { graphql, createRefetchContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import TextField from '@mui/material/TextField';
import { CKEditor } from '@ckeditor/ckeditor5-react';
import Editor from 'ckeditor5-custom-build/build/ckeditor';
import Paper from '@mui/material/Paper';
import { pdfjs, Document, Page } from 'react-pdf';
import inject18n from '../../../../components/i18n';
import StixDomainObjectContentFiles, {
  stixDomainObjectContentFilesUploadStixDomainObjectMutation,
} from './StixDomainObjectContentFiles';
import { APP_BASE_PATH, commitMutation } from '../../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import Loader from '../../../../components/Loader';
import StixDomainObjectContentPdfBar from './StixDomainObjectContentPdfBar';

pdfjs.GlobalWorkerOptions.workerSrc = `${APP_BASE_PATH}/static/pdf.worker.min.js`;

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: '20px 0 0 0',
    padding: '0 350px 90px 0',
  },
  documentContainer: {
    margin: '15px 0 0 0',
    overflow: 'scroll',
    whiteSpace: 'nowrap',
    minWidth: 'calc(100vw - 590px)',
    minHeight: 'calc(100vh - 240px)',
    width: 'calc(100vw - 590px)',
    height: 'calc(100vh - 240px)',
    maxWidth: 'calc(100vw - 590px)',
    maxHeight: 'calc(100vh - 240px)',
    display: 'flex',
    justifyContent: 'center',
    position: 'relative',
  },
  adjustedContainer: {
    margin: '15px 0 0 0',
    overflow: 'hidden',
    whiteSpace: 'nowrap',
    minWidth: 'calc(100vw - 590px)',
    minHeight: 'calc(100vh - 240px)',
    width: 'calc(100vw - 590px)',
    height: 'calc(100vh - 240px)',
    maxWidth: 'calc(100vw - 590px)',
    maxHeight: 'calc(100vh - 240px)',
    display: 'flex',
    justifyContent: 'center',
    position: 'relative',
  },
  editorContainer: {
    height: '100%',
    minHeight: '100%',
    margin: '20px 0 0 0',
    padding: '0 0 15px 0',
    borderRadius: 6,
  },
  pdfViewer: {
    margin: '0 auto',
    textAlign: 'center',
    position: 'relative',
  },
  pdfPage: {
    width: '100%',
    marginBottom: 20,
    textAlign: 'center',
  },
});

const stixDomainObjectContentUploadExternalReferenceMutation = graphql`
  mutation StixDomainObjectContentUploadExternalReferenceMutation(
    $id: ID!
    $file: Upload!
  ) {
    stixDomainObjectEdit(id: $id) {
      importPush(file: $file) {
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

const sortByLastModified = R.sortBy(R.prop('name'));

const getFiles = (stixDomainObject) => {
  const importFiles = R.map(
    (n) => n.node,
    R.pathOr([], ['importFiles', 'edges'], stixDomainObject),
  );
  const externalReferencesFiles = R.pipe(
    R.map((n) => n.node.importFiles.edges),
    R.flatten,
    R.map((n) => n.node),
  )(R.pathOr([], ['externalReferences', 'edges'], stixDomainObject));
  return R.pipe(
    R.filter((n) => ['application/pdf', 'text/plain', 'text/html', 'text/markdown'].includes(
      n.metaData.mimetype,
    )),
    sortByLastModified,
  )([...importFiles, ...externalReferencesFiles]);
};

class StixDomainObjectContentComponent extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-stix-domain-object-content-${props.stixDomainObject.id}`,
    );
    const files = getFiles(props.stixDomainObject);
    this.state = {
      currentFileId: R.propOr(R.head(files)?.id, 'currentFileId', params),
      totalPdfPageNumber: null,
      currentPdfPageNumber: 1,
      pdfViewerZoom: 2,
      initialContent: props.t('Write something awesome...'),
      currentContent: props.t('Write something awesome...'),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-stix-domain-object-content-${this.props.stixDomainObject.id}`,
      this.state,
    );
  }

  loadFileContent() {
    const { stixDomainObject } = this.props;
    const files = getFiles(stixDomainObject);
    this.setState({ isLoading: true }, () => {
      const { currentFileId } = this.state;
      if (!currentFileId) {
        return this.setState({ isLoading: false });
      }
      const currentFile = currentFileId && R.head(R.filter((n) => n.id === currentFileId, files));
      const currentFileType = currentFile && currentFile.metaData.mimetype;
      if (currentFileType === 'application/pdf') {
        return this.setState({ isLoading: false });
      }
      const url = `${APP_BASE_PATH}/storage/view/${currentFileId}`;
      return Axios.get(url).then((res) => {
        const content = res.data;
        return this.setState({
          initialContent: content,
          currentContent: content,
          isLoading: false,
        });
      });
    });
  }

  componentWillMount() {
    if (this.props.theme.palette.type === 'dark') {
      // eslint-disable-next-line global-require
      require('../../../../resources/css/CKEditorDark.css');
    } else {
      // eslint-disable-next-line global-require
      require('../../../../resources/css/CKEditorLight.css');
    }
  }

  componentDidMount() {
    this.loadFileContent();
  }

  handleSelectFile(fileId) {
    this.setState({ currentFileId: fileId }, () => {
      this.loadFileContent();
      this.saveView();
    });
  }

  handleFileChange(fileName = null) {
    this.props.relay.refetch({ id: this.props.stixDomainObject.id });
    if (fileName && fileName === this.state.currentFileId) {
      this.setState({ currentFileId: null }, () => this.saveView());
    } else if (fileName) {
      this.setState({ currentFileId: fileName }, () => {
        this.loadFileContent();
        this.saveView();
      });
    }
  }

  // PDF SECTION
  onDocumentLoadSuccess({ numPages: nextNumPages }) {
    this.setState({ totalPdfPageNumber: nextNumPages });
  }

  handleZoomIn() {
    this.setState({ pdfViewerZoom: this.state.pdfViewerZoom + 0.2 }, () => this.saveView());
  }

  handleZoomOut() {
    this.setState({ pdfViewerZoom: this.state.pdfViewerZoom - 0.2 }, () => this.saveView());
  }
  // END OF PDF SECTION

  prepareSaveFile() {
    const { stixDomainObject } = this.props;
    const { currentFileId } = this.state;
    const files = getFiles(stixDomainObject);
    const currentFile = currentFileId && R.head(R.filter((n) => n.id === currentFileId, files));
    const currentFileType = currentFile && currentFile.metaData.mimetype;
    const fragment = currentFileId.split('/');
    const currentName = R.last(fragment);
    const currentId = fragment[fragment.length - 2];
    const currentType = fragment[fragment.length - 3];
    const isExternalReference = currentType === 'External-Reference';
    const content = this.state.currentContent;
    const blob = new Blob([content], {
      type: currentFileType,
    });
    const file = new File([blob], currentName, {
      type: currentFileType,
    });
    return { currentId, isExternalReference, file };
  }

  saveFile() {
    const { currentId, isExternalReference, file } = this.prepareSaveFile();
    commitMutation({
      mutation: isExternalReference
        ? stixDomainObjectContentUploadExternalReferenceMutation
        : stixDomainObjectContentFilesUploadStixDomainObjectMutation,
      variables: { file, id: currentId },
    });
  }

  onTextFieldChange(event) {
    this.setState({ currentContent: event.target.value });
  }

  onHtmlFieldChange(content) {
    this.setState({ currentContent: content });
  }

  render() {
    const { classes, stixDomainObject, t } = this.props;
    const {
      currentFileId,
      totalPdfPageNumber,
      isLoading,
      initialContent,
      currentContent,
    } = this.state;
    const files = getFiles(stixDomainObject);
    const currentUrl = currentFileId && `${APP_BASE_PATH}/storage/view/${currentFileId}`;
    const currentGetUrl = currentFileId && `${APP_BASE_PATH}/storage/get/${currentFileId}`;
    const currentFile = currentFileId && R.head(R.filter((n) => n.id === currentFileId, files));
    const currentFileType = currentFile && currentFile.metaData.mimetype;
    const { innerHeight } = window;
    const height = innerHeight - 250;
    return (
      <div className={classes.container}>
        <StixDomainObjectContentFiles
          stixDomainObjectId={stixDomainObject.id}
          files={files}
          handleSelectFile={this.handleSelectFile.bind(this)}
          currentFileId={currentFileId}
          onFileChange={this.handleFileChange.bind(this)}
        />
        {currentFileType === 'text/plain' && (
          <div
            className={classes.editorContainer}
            style={{ minHeight: height }}
          >
            {isLoading ? (
              <Loader variant="inElement" />
            ) : (
              <TextField
                variant="standard"
                style={{ height: '100%' }}
                key={currentFile.id}
                id={currentFile.id}
                defaultValue={initialContent}
                value={currentContent}
                multiline={true}
                onBlur={this.saveFile.bind(this)}
                onChange={this.onTextFieldChange.bind(this)}
                fullWidth={true}
              />
            )}
          </div>
        )}
        {currentFileType === 'text/html' && (
          <Paper
            classes={{ root: classes.editorContainer }}
            elevation={2}
            style={{ minHeight: height }}
          >
            {isLoading ? (
              <Loader variant="inElement" />
            ) : (
              <CKEditor
                editor={Editor}
                config={{
                  width: '100%',
                }}
                data={currentContent}
                onChange={(event, editor) => {
                  this.onHtmlFieldChange(editor.getData());
                }}
                onBlur={() => {
                  this.saveFile.bind(this);
                }}
              />
            )}
          </Paper>
        )}
        {currentFileType === 'text/markdown' && (
          <Paper
            classes={{ root: classes.editorContainer }}
            elevation={2}
            style={{ minHeight: height }}
          >
            {isLoading ? (
              <Loader variant="inElement" />
            ) : (
              <TextField
                style={{ height: '100%' }}
                key={currentFile.id}
                id={currentFile.id}
                defaultValue={initialContent}
                value={currentContent}
                multiline={true}
                onBlur={this.saveFile.bind(this)}
                onChange={this.onTextFieldChange.bind(this)}
                fullWidth={true}
              />
            )}
          </Paper>
        )}
        {currentFileType === 'application/pdf' && (
          <div>
            <StixDomainObjectContentPdfBar
              handleZoomIn={this.handleZoomIn.bind(this)}
              handleZoomOut={this.handleZoomOut.bind(this)}
              directDownload={currentGetUrl}
              currentZoom={this.state.pdfViewerZoom}
            />
            <div className={classes.documentContainer}>
              <Document
                className={classes.pdfViewer}
                onLoadSuccess={this.onDocumentLoadSuccess.bind(this)}
                loading={<Loader variant="inElement" />}
                file={currentUrl}
              >
                {Array.from(new Array(totalPdfPageNumber), (el, index) => (
                  <Page
                    key={`page_${index + 1}`}
                    className={classes.pdfPage}
                    pageNumber={index + 1}
                    height={height}
                    scale={this.state.pdfViewerZoom}
                  />
                ))}
              </Document>
            </div>
          </div>
        )}
        {!currentFile && (
          <div className={classes.adjustedContainer}>
            <div
              style={{
                display: 'table',
                height: '100%',
                width: '100%',
              }}
            >
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                {t('No file selected.')}
              </span>
            </div>
          </div>
        )}
      </div>
    );
  }
}

StixDomainObjectContentComponent.propTypes = {
  stixDomainObject: PropTypes.object,
  theme: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixDomainObjectContentRefetchQuery = graphql`
  query StixDomainObjectContentRefetchQuery($id: String!) {
    stixDomainObject(id: $id) {
      ...StixDomainObjectContent_stixDomainObject
    }
  }
`;

const StixDomainObjectContent = createRefetchContainer(
  StixDomainObjectContentComponent,
  {
    stixDomainObject: graphql`
      fragment StixDomainObjectContent_stixDomainObject on StixDomainObject {
        id
        importFiles(first: 1000) {
          edges {
            node {
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
        externalReferences {
          edges {
            node {
              source_name
              url
              description
              importFiles(first: 1000) {
                edges {
                  node {
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
            }
          }
        }
      }
    `,
  },
  stixDomainObjectContentRefetchQuery,
);

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixDomainObjectContent);
