import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import Axios from 'axios';
import { createRefetchContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import TextField from '@mui/material/TextField';
import { Document, Page, pdfjs } from 'react-pdf';
import 'react-pdf/dist/esm/Page/TextLayer.css';
import 'react-pdf/dist/esm/Page/AnnotationLayer.css';
import ReactMde from 'react-mde';
import { interval } from 'rxjs';
import StixCoreObjectMappableContent from './StixCoreObjectMappableContent';
import TextFieldAskAI from '../form/TextFieldAskAI';
import inject18n from '../../../../components/i18n';
import StixCoreObjectContentFiles, { stixCoreObjectContentFilesUploadStixCoreObjectMutation } from './StixCoreObjectContentFiles';
import { APP_BASE_PATH, commitMutation, MESSAGING$ } from '../../../../relay/environment';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectContentBar from './StixCoreObjectContentBar';
import { isEmptyField } from '../../../../utils/utils';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import { FIVE_SECONDS } from '../../../../utils/Time';
import withRouter from '../../../../utils/compat_router/withRouter';
import CKEditor from '../../../../components/CKEditor';
import { htmlToPdf } from '../../../../utils/htmlToPdf/htmlToPdf';

pdfjs.GlobalWorkerOptions.workerSrc = `${APP_BASE_PATH}/static/ext/pdf.worker.mjs`;

const styles = (theme) => ({
  container: {
    width: '100%',
    height: '100%',
    marginTop: theme.spacing(1),
  },
  documentContainer: {
    margin: '5px 0 0 0',
    overflow: 'scroll',
    whiteSpace: 'nowrap',
    minWidth: 'calc(100vw - 455px)',
    minHeight: 'calc(100vh - 300px)',
    width: 'calc(100vw - 455px)',
    height: 'calc(100vh - 300px)',
    maxWidth: 'calc(100vw - 455px)',
    maxHeight: 'calc(100vh - 300px)',
    display: 'flex',
    justifyContent: 'center',
  },
  adjustedContainer: {
    margin: '5px 0 0 0',
    overflow: 'hidden',
    whiteSpace: 'nowrap',
    minWidth: 'calc(100vw - 465px)',
    minHeight: 'calc(100vh - 310px)',
    width: 'calc(100vw - 465px)',
    height: 'calc(100vh - 310px)',
    maxWidth: 'calc(100vw - 465px)',
    maxHeight: 'calc(100vh - 310px)',
    display: 'flex',
    justifyContent: 'center',
    position: 'relative',
  },
  documentContainerNavOpen: {
    margin: '5px 0 0 0',
    overflow: 'scroll',
    whiteSpace: 'nowrap',
    minWidth: 'calc(100vw - 580px)',
    minHeight: 'calc(100vh - 310px)',
    width: 'calc(100vw - 580px)',
    height: 'calc(100vh - 310px)',
    maxWidth: 'calc(100vw - 580px)',
    maxHeight: 'calc(100vh - 310px)',
    display: 'flex',
    justifyContent: 'center',
  },
  adjustedContainerNavOpen: {
    margin: '5px 0 0 0',
    overflow: 'hidden',
    whiteSpace: 'nowrap',
    minWidth: 'calc(100vw - 590px)',
    minHeight: 'calc(100vh - 310px)',
    width: 'calc(100vw - 590px)',
    height: 'calc(100vh - 310px)',
    maxWidth: 'calc(100vw - 590px)',
    maxHeight: 'calc(100vh - 310px)',
    display: 'flex',
    justifyContent: 'center',
    position: 'relative',
  },
  editorContainer: {
    height: '100%',
    minHeight: '100%',
    padding: `0 0 ${theme.spacing(2)} 0`,
    borderRadius: 4,
    position: 'relative',
  },
  editorContainerPreview: {
    overflowY: 'scroll',
    overflowX: 'hidden',
  },
});

const interval$ = interval(FIVE_SECONDS);

const stixCoreObjectContentUploadExternalReferenceMutation = graphql`
  mutation StixCoreObjectContentUploadExternalReferenceMutation(
    $id: ID!
    $file: Upload!
    $fileMarkings: [String]
  ) {
    stixCoreObjectEdit(id: $id) {
      importPush(file: $file, noTriggerImport: true, fileMarkings: $fileMarkings) {
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

const sortByLastModified = R.sortBy(R.prop('lastModified'));

const getFiles = (stixCoreObject) => {
  const importFiles = stixCoreObject.importFiles?.edges
    ?.filter((n) => !!n?.node)
    .map((n) => n.node) ?? [];
  const externalReferencesFiles = stixCoreObject.externalReferences?.edges
    ?.map((n) => n?.node?.importFiles?.edges)
    .flat()
    .filter((n) => !!n?.node)
    .map((n) => n.node)
    .filter(
      (n) => n.metaData && isEmptyField(n.metaData.external_reference_id),
    ) ?? [];
  return sortByLastModified(
    [...importFiles, ...externalReferencesFiles].filter((n) => {
      return [
        'application/pdf',
        'text/plain',
        'text/html',
        'text/markdown',
      ].includes(n.metaData.mimetype);
    }),
  );
};

const getFilesFromTemplate = (stixCoreObject) => {
  const filesFromTemplate = stixCoreObject.filesFromTemplate?.edges
    ?.filter((n) => !!n?.node)
    .map((n) => n.node) ?? [];
  return sortByLastModified(filesFromTemplate);
};

const getExportFiles = (stixCoreObject) => {
  const exportFiles = stixCoreObject.exportFiles?.edges
    ?.filter((n) => !!n?.node)
    .map((n) => n.node) ?? [];
  return sortByLastModified(
    [...exportFiles].filter((n) => {
      return (
        ['application/pdf'].includes(n.metaData.mimetype)
        || n.uploadStatus === 'progress'
      );
    }),
  );
};

const isContainerWithContent = (type) => ['Report', 'Grouping', 'Case-Incident', 'Case-Rfi', 'Case-Rft'].includes(type);

class StixCoreObjectContentComponent extends Component {
  constructor(props) {
    const LOCAL_STORAGE_KEY = `stix-core-object-content-${props.stixCoreObject.id}`;
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.navigate,
      props.location,
      LOCAL_STORAGE_KEY,
    );
    const { stixCoreObject } = props;
    const isContentCompatible = isContainerWithContent(stixCoreObject.entity_type);
    const files = getFiles(stixCoreObject);
    const exportFiles = getExportFiles(stixCoreObject);
    let currentFileId = isEmptyField(stixCoreObject.contentField) ? R.head(files)?.id : null;
    let isLoading = false;
    let onProgressExportFileName;
    if (params.currentFileId && (!params.contentSelected || params.forceFile)) {
      const onProgressExportFile = exportFiles.find(
        (file) => file.id === params.currentFileId && file.uploadStatus === 'progress',
      );
      if (onProgressExportFile) {
        isLoading = true;
        onProgressExportFileName = onProgressExportFile.name;
      }
      currentFileId = params.currentFileId;
    }
    this.state = {
      currentFileId: isContentCompatible && params.contentSelected && params.forceFile !== true ? null : currentFileId,
      contentSelected: isContentCompatible && params.forceFile !== true && (params.contentSelected || isEmptyField(currentFileId)),
      totalPdfPageNumber: null,
      currentPdfPageNumber: 1,
      pdfViewerZoom: 1.2,
      markdownSelectedTab: 'write',
      initialContent: isContentCompatible ? stixCoreObject.contentField : props.t('Write something awesome...'),
      currentContent: isContentCompatible ? stixCoreObject.contentField : props.t('Write something awesome...'),
      navOpen: localStorage.getItem('navOpen') === 'true',
      changed: false,
      isLoading,
      onProgressExportFileName,
    };
  }

  saveView() {
    const LOCAL_STORAGE_KEY = `stix-core-object-content-${this.props.stixCoreObject.id}`;
    saveViewParameters(
      this.props.navigate,
      this.props.location,
      LOCAL_STORAGE_KEY,
      this.state,
    );
  }

  loadFileContent() {
    const { stixCoreObject } = this.props;
    const files = [
      ...getFiles(stixCoreObject),
      ...getExportFiles(stixCoreObject),
      ...getFilesFromTemplate(stixCoreObject),
    ];
    this.setState({ isLoading: true }, () => {
      const { currentFileId } = this.state;
      if (!currentFileId) {
        return this.setState({ isLoading: false });
      }
      const currentFile = files.find((f) => f.id === currentFileId);
      const currentFileType = currentFile && currentFile.metaData.mimetype;
      if (currentFileType === 'application/pdf') {
        return this.setState({ isLoading: false });
      }
      const url = `${APP_BASE_PATH}/storage/view/${encodeURIComponent(
        currentFileId,
      )}`;
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

  componentDidMount() {
    this.subscriptionToggle = MESSAGING$.toggleNav.subscribe({
      next: () => this.setState({ navOpen: localStorage.getItem('navOpen') === 'true' }),
    });
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch({ id: this.props.stixCoreObject.id });
    });

    const { stixCoreObject } = this.props;
    const { currentFileId } = this.state;
    const files = [
      ...getFiles(stixCoreObject),
      ...getExportFiles(stixCoreObject),
      ...getFilesFromTemplate(stixCoreObject),
    ];
    const currentFile = files.find((f) => f.id === currentFileId);

    if (currentFile?.uploadStatus !== 'progress') {
      this.loadFileContent();
    }
  }

  componentDidUpdate() {
    const { onProgressExportFileName } = this.state;
    const { stixCoreObject } = this.props;
    const exportFiles = getExportFiles(stixCoreObject);

    if (onProgressExportFileName) {
      const exportFile = exportFiles.find(
        (file) => file.name === onProgressExportFileName,
      );
      if (exportFile?.uploadStatus === 'complete') {
        this.handleSelectFile(exportFile.id);
        this.setState({
          onProgressExportFileName: undefined,
        });
        this.subscription.unsubscribe();
      }
    }
  }

  componentWillUnmount() {
    this.subscriptionToggle.unsubscribe();
    this.subscription.unsubscribe();
  }

  handleSelectContent() {
    const { stixCoreObject, t } = this.props;
    this.setState({
      currentFileId: null,
      changed: false,
      contentSelected: true,
      currentContent: stixCoreObject.contentField ?? t('Write something awesome...'),
    }, () => {
      this.props.setMappingHeaderDisabled(false);
      this.saveView();
    });
  }

  handleSelectFile(fileId) {
    this.setState({ currentFileId: fileId, changed: false, contentSelected: false }, () => {
      this.props.setMappingHeaderDisabled(true);
      this.loadFileContent();
      this.saveView();
    });
  }

  handleFileChange(fileName = null, isDelete = false) {
    const { t, stixCoreObject } = this.props;
    this.props.relay.refetch({ id: stixCoreObject.id });
    if (fileName && fileName === this.state.currentFileId && isDelete) {
      this.setState({
        currentFileId: null,
        contentSelected: isContainerWithContent(stixCoreObject.entity_type),
        currentContent: isContainerWithContent(stixCoreObject.entity_type) ? stixCoreObject.contentField ?? t('Write something awesome...') : '',
      }, () => this.saveView());
    } else if (fileName && !isDelete) {
      this.setState({ currentFileId: fileName, contentSelected: false }, () => {
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
    const { stixCoreObject } = this.props;
    const { currentFileId } = this.state;
    const files = [...getFiles(stixCoreObject), ...getFilesFromTemplate(stixCoreObject)];
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
    return { currentId, isExternalReference, file, currentFile };
  }

  saveFile() {
    const { currentId, isExternalReference, file, currentFile } = this.prepareSaveFile();
    const { file_markings: fileMarkings } = currentFile.metaData;

    commitMutation({
      mutation: isExternalReference
        ? stixCoreObjectContentUploadExternalReferenceMutation
        : stixCoreObjectContentFilesUploadStixCoreObjectMutation,
      variables: {
        file,
        id: currentId,
        noTriggerImport: true,
        fileMarkings,
        fromTemplate: !!currentFile.id.startsWith('fromTemplate/'),
      },
      onCompleted: () => this.setState({ changed: false }),
    });
  }

  onTextFieldChange(event) {
    this.setState({ currentContent: event.target.value, changed: true });
  }

  onHtmlFieldChange(content) {
    this.setState({ currentContent: content });
  }

  onMarkDownFieldChange(value) {
    this.setState({ currentContent: value, changed: true });
  }

  onMarkdownChangeTab(tab) {
    this.setState({ markdownSelectedTab: tab });
  }

  async handleDownloadMappableContentInPdf() {
    const { currentContent } = this.state;
    const { stixCoreObject } = this.props;
    const regex = /<img[^>]+src=(\\?["'])[^'"]+\.gif\1[^>]*\/?>/gi;
    const htmlData = currentContent
      .replaceAll('id="undefined" ', '')
      .replaceAll(regex, '');
    const fragment = stixCoreObject.name.split('/');
    const currentName = R.last(fragment);
    htmlToPdf('content', htmlData).download(`${currentName}.pdf`);
  }

  render() {
    const { classes, stixCoreObject, t } = this.props;
    const {
      currentFileId,
      totalPdfPageNumber,
      isLoading,
      currentContent,
      markdownSelectedTab,
      navOpen,
      changed,
      contentSelected,
    } = this.state;
    const files = getFiles(stixCoreObject);
    const exportFiles = getExportFiles(stixCoreObject);
    const filesFromTemplate = getFilesFromTemplate(stixCoreObject);
    const currentUrl = currentFileId
      && `${APP_BASE_PATH}/storage/view/${encodeURIComponent(currentFileId)}`;
    const currentFile = currentFileId
      && [...files, ...exportFiles, ...filesFromTemplate].find((n) => n.id === currentFileId);
    const currentFileType = currentFile && currentFile.metaData.mimetype;
    const { innerHeight } = window;
    const height = innerHeight - 320;
    const isContentCompatible = isContainerWithContent(stixCoreObject.entity_type);
    return (
      <div className={classes.container} data-testid='sco-content-page'>
        <StixCoreObjectContentFiles
          stixCoreObjectId={stixCoreObject.id}
          stixCoreObjectName={stixCoreObject.name}
          stixCoreObjectType={stixCoreObject.entity_type}
          content={isContentCompatible ? stixCoreObject.contentField ?? '' : null}
          contentSelected={contentSelected}
          files={files}
          exportFiles={exportFiles}
          handleSelectContent={this.handleSelectContent.bind(this)}
          handleSelectFile={this.handleSelectFile.bind(this)}
          currentFileId={currentFileId}
          onFileChange={this.handleFileChange.bind(this)}
          filesFromTemplate={filesFromTemplate}
          hasOutcomesTemplate={isContentCompatible}
        />
        {isLoading ? (
          <Loader variant={LoaderVariant.inElement} />
        ) : (
          <>
            {contentSelected && (
              <StixCoreObjectMappableContent
                containerData={stixCoreObject}
                handleDownloadPdf={this.handleDownloadMappableContentInPdf.bind(this)}
                askAi={true}
                editionMode={true}
              />
            )}
            {currentFileType === 'text/plain' && (
              <>
                <StixCoreObjectContentBar
                  navOpen={navOpen}
                  handleSave={this.saveFile.bind(this)}
                  changed={changed}
                />
                <div
                  className={classes.editorContainer}
                  style={{ minHeight: height }}
                >
                  <TextField
                    rows={Math.round(height / 23)}
                    key={currentFile.id}
                    id={currentFile.id}
                    value={currentContent ?? ''}
                    multiline={true}
                    onChange={this.onTextFieldChange.bind(this)}
                    fullWidth={true}
                    InputProps={{
                      endAdornment: (
                        <TextFieldAskAI
                          currentValue={currentContent ?? ''}
                          setFieldValue={(val) => {
                            this.onTextFieldChange({ target: { value: val } });
                          }}
                          format="text"
                          variant="text"
                        />
                      ),
                    }}
                  />
                </div>
              </>
            )}
            {(currentFileType === 'text/html') && (
              <>
                <StixCoreObjectContentBar
                  handleSave={() => (this.saveFile())}
                  changed={changed}
                  navOpen={navOpen}
                />
                <div
                  className={classes.editorContainer}
                  style={{ minHeight: height, height }}
                >
                  <CKEditor
                    data={currentContent ?? ''}
                    onChange={() => {
                      this.setState({ changed: true });
                    }}
                    onBlur={(_, editor) => {
                      this.onHtmlFieldChange(editor.getData());
                    }}
                  />
                  <TextFieldAskAI
                    currentValue={currentContent ?? ''}
                    setFieldValue={(val) => {
                      this.onHtmlFieldChange(val);
                    }}
                    format="html"
                    variant="html"
                    style={{ position: 'absolute', top: 0, right: 10 }}
                  />
                </div>
              </>
            )}
            {currentFileType === 'text/markdown' && (
              <>
                <StixCoreObjectContentBar
                  navOpen={navOpen}
                  handleSave={this.saveFile.bind(this)}
                  changed={changed}
                />
                <div
                  className={classes.editorContainer}
                  style={{ minHeight: height, height }}
                >
                  <ReactMde
                    value={currentContent ?? ''}
                    minEditorHeight={height - 80}
                    maxEditorHeight={height - 80}
                    onChange={this.onMarkDownFieldChange.bind(this)}
                    selectedTab={markdownSelectedTab}
                    onTabChange={this.onMarkdownChangeTab.bind(this)}
                    generateMarkdownPreview={(markdown) => Promise.resolve(
                      <div className={classes.editorContainerPreview} style={{ height: height - 80, maxHeight: height - 80 }}>
                        <MarkdownDisplay
                          content={markdown}
                          remarkGfmPlugin={true}
                          commonmark={true}
                        />
                      </div>,
                    )
                    }
                    l18n={{
                      write: t('Write'),
                      preview: t('Preview'),
                      uploadingImage: t('Uploading image'),
                      pasteDropSelect: t('Paste'),
                    }}
                  />
                  <TextFieldAskAI
                    currentValue={currentContent ?? ''}
                    setFieldValue={(val) => {
                      this.onMarkDownFieldChange(val);
                    }}
                    format="markdown"
                    variant="markdown"
                  />
                </div>
              </>
            )}
            {currentFileType === 'application/pdf' && (
              <>
                <StixCoreObjectContentBar
                  handleZoomIn={this.handleZoomIn.bind(this)}
                  handleZoomOut={this.handleZoomOut.bind(this)}
                  currentZoom={this.state.pdfViewerZoom}
                  navOpen={navOpen}
                />
                <div
                  className={
                    navOpen
                      ? classes.documentContainerNavOpen
                      : classes.documentContainer
                  }
                >
                  <Document
                    onLoadSuccess={this.onDocumentLoadSuccess.bind(this)}
                    loading={<Loader variant="inElement" />}
                    file={currentUrl}
                  >
                    {Array.from(new Array(totalPdfPageNumber), (el, index) => (
                      <Page
                        key={`page_${index + 1}`}
                        pageNumber={index + 1}
                        height={height}
                        scale={this.state.pdfViewerZoom}
                      />
                    ))}
                  </Document>
                </div>
              </>
            )}
            {!currentFile && !contentSelected && (
              <div
                className={
                  navOpen
                    ? classes.adjustedContainerNavOpen
                    : classes.adjustedContainer
                }
              >
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
          </>
        )}
      </div>
    );
  }
}

StixCoreObjectContentComponent.propTypes = {
  stixCoreObject: PropTypes.object,
  setMappingHeaderDisabled: PropTypes.func,
  theme: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixCoreObjectContentRefetchQuery = graphql`
  query StixCoreObjectContentRefetchQuery($id: String!) {
    stixCoreObject(id: $id) {
      ...StixCoreObjectContent_stixCoreObject
    }
  }
`;

const StixCoreObjectContent = createRefetchContainer(
  StixCoreObjectContentComponent,
  {
    stixCoreObject: graphql`
      fragment StixCoreObjectContent_stixCoreObject on StixCoreObject {
        id
        entity_type
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        ... on Report {
          name
          description
          contentField: content
          content_mapping
          editContext {
            name
            focusOn
          }
        }
        ... on Case {
          name
          description
          contentField: content
          content_mapping
          editContext {
            name
            focusOn
          }
        }
        ... on Grouping {
          name
          description
          contentField: content
          content_mapping
          editContext {
            name
            focusOn
          }
        }
        importFiles(first: 500) @connection(key: "Pagination_importFiles") {
          edges {
            node {
              id
              name
              uploadStatus
              lastModified
              lastModifiedSinceMin
              objectMarking {
                id
                x_opencti_color
                definition
              }
              metaData {
                mimetype
                list_filters
                file_markings
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
        exportFiles(first: 500) @connection(key: "Pagination_exportFiles") {
          edges {
            node {
              id
              name
              uploadStatus
              lastModified
              lastModifiedSinceMin
              objectMarking {
                id
                x_opencti_color
                definition
              }
              metaData {
                mimetype
                file_markings
              }
              ...FileLine_file
            }
          }
        }
        ... on Container {
          filesFromTemplate(first: 500) @connection(key: "Pagination_filesFromTemplate") {
            edges {
              node {
                id
                name
                uploadStatus
                lastModified
                lastModifiedSinceMin
                objectMarking {
                  id
                  x_opencti_color
                  definition
                }
                  metaData {
                    mimetype
                    list_filters
                    file_markings
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
          fintelTemplates {
            id
            name
            content
          }
        }
        externalReferences {
          edges {
            node {
              source_name
              url
              description
              importFiles(first: 500) {
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
                      external_reference_id
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
  stixCoreObjectContentRefetchQuery,
);

export default R.compose(
  inject18n,
  withTheme,
  withRouter,
  withStyles(styles),
)(StixCoreObjectContent);
