import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import Axios from 'axios';
import { createRefetchContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import TextField from '@mui/material/TextField';
import htmlToPdfmake from 'html-to-pdfmake';
import pdfMake from 'pdfmake';
import { CKEditor } from '@ckeditor/ckeditor5-react';
import Editor from 'ckeditor5-custom-build/build/ckeditor';
import 'ckeditor5-custom-build/build/translations/fr';
import 'ckeditor5-custom-build/build/translations/zh-cn';
import { Document, Page, pdfjs } from 'react-pdf';
import 'react-pdf/dist/esm/Page/TextLayer.css';
import 'react-pdf/dist/esm/Page/AnnotationLayer.css';
import ReactMde from 'react-mde';
import { interval } from 'rxjs';
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
import withRouter from '../../../../utils/compat-router/withRouter';

pdfjs.GlobalWorkerOptions.workerSrc = `${APP_BASE_PATH}/static/ext/pdf.worker.mjs`;

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: '10px 0 0 0',
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
    margin: '20px 0 0 0',
    padding: '0 0 15px 0',
    borderRadius: 4,
    position: 'relative',
  },
});

const interval$ = interval(FIVE_SECONDS);

export const stixDomainObjectContentFieldPatchMutation = graphql`
  mutation StixCoreObjectContentFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(input: $input, commitMessage: $commitMessage, references: $references) {
        ...StixCoreObjectContent_stixCoreObject
      }
    }
  }
`;

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
    this.setState({ currentFileId: null, changed: false, contentSelected: true, currentContent: stixCoreObject.contentField ?? t('Write something awesome...') }, () => {
      this.saveView();
    });
  }

  handleSelectFile(fileId) {
    this.setState({ currentFileId: fileId, changed: false, contentSelected: false }, () => {
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
    const files = getFiles(stixCoreObject);
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
      variables: { file, id: currentId, noTriggerImport: true, fileMarkings },
      onCompleted: () => this.setState({ changed: false }),
    });
  }

  saveContent() {
    const { id } = this.props.stixCoreObject;
    const inputValues = [{ key: 'content', value: this.state.currentContent }];
    // Currently, only containers have a content available, so this mutation targets SDOs only. If content is added to all Stix Core Objects,
    // this mutation will need to be updated to a stixCoreObjectEdit instead of a stixDomainObjectEdit
    commitMutation({
      mutation: stixDomainObjectContentFieldPatchMutation,
      variables: {
        id,
        input: inputValues,
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

  handleDownloadPdf() {
    const { currentFileId, currentContent } = this.state;
    const { stixCoreObject } = this.props;
    const regex = /<img[^>]+src=(\\?["'])[^'"]+\.gif\1[^>]*\/?>/gi;
    const htmlData = currentContent
      .replaceAll('id="undefined" ', '')
      .replaceAll(regex, '');
    const ret = htmlToPdfmake(htmlData, {
      imagesByReference: true,
      ignoreStyles: ['font-family'],
    });
    Promise.all(
      R.pipe(
        R.toPairs,
        R.map((n) => {
          if (n[1].includes('data:')) {
            const split = n[1].split(',');
            const mime = split[0].split(';')[0].split(':')[1];
            const data = split[1];
            return {
              ref: n[0],
              mime,
              data,
            };
          }
          return Axios.get(n[1], { responseType: 'arraybuffer' })
            .then((response) => {
              if (
                ['image/jpeg', 'image/png'].includes(
                  response.headers['content-type'],
                )
              ) {
                return {
                  ref: n[0],
                  mime: response.headers['content-type'],
                  data: Buffer.from(response.data, 'binary').toString('base64'),
                };
              }
              return null;
            })
            .catch(() => null);
        }),
        R.filter((n) => n !== null),
      )(ret.images),
    ).then((result) => {
      const imagesIndex = R.indexBy(R.prop('ref'), result);
      const images = R.pipe(
        R.toPairs,
        R.map((n) => (imagesIndex[n[0]]
          ? [
            n[0],
            `data:${imagesIndex[n[0]].mime};base64,${
              imagesIndex[n[0]].data
            }`,
          ]
          : [
            n[0],
            'data:image/png;base64,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',
          ])),
        R.fromPairs,
      )(ret.images);

      let pdfElementMaxWidth = 0;
      // We need to get tables width inside ckeditor in order to know which mode we should save the PDF
      const elementCkEditor = document.querySelector(
        '.ck-content.ck-editor__editable.ck-editor__editable_inline',
      );
      if (elementCkEditor) {
        Array.from(
          elementCkEditor.querySelectorAll('figure.table') ?? [],
        ).forEach((c) => {
          if (c.offsetWidth > pdfElementMaxWidth) {
            pdfElementMaxWidth = c.offsetWidth;
          }
        });
      }
      const maxContentForPortraitMode = 680;
      const pageOrientation = pdfElementMaxWidth > maxContentForPortraitMode
        ? 'landscape'
        : 'portrait';
      const pdfData = {
        content: ret.content,
        images,
        pageOrientation,
      };
      const { protocol, hostname, port } = window.location;
      const url = `${protocol}//${hostname}:${port || ''}`;
      const fonts = {
        Roboto: {
          normal: `${url}${APP_BASE_PATH}/static/ext/Roboto-Regular.ttf`,
          bold: `${url}${APP_BASE_PATH}/static/ext/Roboto-Bold.ttf`,
          italics: `${url}${APP_BASE_PATH}/static/ext/Roboto-Italic.ttf`,
          bolditalics: `${url}${APP_BASE_PATH}/static/ext/Roboto-BoldItalic.ttf`,
        },
      };
      const fragment = (currentFileId ?? stixCoreObject.name).split('/');
      const currentName = R.last(fragment);
      pdfMake.createPdf(pdfData, null, fonts).download(`${currentName}.pdf`);
    });
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
    const currentUrl = currentFileId
      && `${APP_BASE_PATH}/storage/view/${encodeURIComponent(currentFileId)}`;
    const currentGetUrl = currentFileId
      && `${APP_BASE_PATH}/storage/get/${encodeURIComponent(currentFileId)}`;
    const currentFile = currentFileId
      && [...files, ...exportFiles].find((n) => n.id === currentFileId);
    const currentFileType = currentFile && currentFile.metaData.mimetype;
    const { innerHeight } = window;
    const height = innerHeight - 270;
    const isContentCompatible = isContainerWithContent(stixCoreObject.entity_type);
    return (
      <div className={classes.container} data-testid="sdo-content-page">
        <StixCoreObjectContentFiles
          stixCoreObjectId={stixCoreObject.id}
          content={isContentCompatible ? stixCoreObject.contentField ?? '' : null}
          contentSelected={contentSelected}
          files={files}
          exportFiles={exportFiles}
          handleSelectContent={this.handleSelectContent.bind(this)}
          handleSelectFile={this.handleSelectFile.bind(this)}
          handleSelectExportFile={this.handleSelectFile.bind(this)}
          currentFileId={currentFileId}
          onFileChange={this.handleFileChange.bind(this)}
        />
        {isLoading ? (
          <Loader variant={LoaderVariant.inElement} />
        ) : (
          <>
            {currentFileType === 'text/plain' && (
              <>
                <StixCoreObjectContentBar
                  directDownload={currentGetUrl}
                  handleDownloadPdf={this.handleDownloadPdf.bind(this)}
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
            {(currentFileType === 'text/html' || contentSelected) && (
              <>
                <StixCoreObjectContentBar
                  directDownload={currentGetUrl}
                  handleDownloadPdf={this.handleDownloadPdf.bind(this)}
                  handleSave={() => (contentSelected ? this.saveContent() : this.saveFile())}
                  changed={changed}
                  navOpen={navOpen}
                />
                <div
                  className={classes.editorContainer}
                  style={{ minHeight: height, height }}
                >
                  <CKEditor
                    editor={Editor}
                    config={{
                      language: 'en',
                      toolbar: { shouldNotGroupWhenFull: true },
                    }}
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
                  directDownload={currentGetUrl}
                  handleDownloadPdf={this.handleDownloadPdf.bind(this)}
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
                      <MarkdownDisplay
                        content={markdown}
                        remarkGfmPlugin={true}
                        commonmark={true}
                      />,
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
                  directDownload={currentGetUrl}
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
            {!currentFile && (
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
              metaData {
                mimetype
                file_markings
              }
              ...FileLine_file
            }
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
