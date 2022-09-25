import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import Axios from 'axios';
import { graphql, createRefetchContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import TextField from '@mui/material/TextField';
import htmlToPdfmake from 'html-to-pdfmake';
import pdfMake from 'pdfmake';
import { CKEditor } from '@ckeditor/ckeditor5-react';
import Editor from 'ckeditor5-custom-build/build/ckeditor';
import 'ckeditor5-custom-build/build/translations/fr';
import 'ckeditor5-custom-build/build/translations/zh-cn';
import { pdfjs, Document, Page } from 'react-pdf';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import ReactMde from 'react-mde';
import { Subject, timer } from 'rxjs';
import { debounce } from 'rxjs/operators';
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
import StixDomainObjectContentBar from './StixDomainObjectContentBar';

pdfjs.GlobalWorkerOptions.workerSrc = `${APP_BASE_PATH}/static/ext/pdf.worker.min.js`;

const SAVE$ = new Subject().pipe(debounce(() => timer(2000)));

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: '20px 0 0 0',
    padding: '0 350px 0 0',
  },
  documentContainer: {
    margin: '15px 0 0 0',
    overflow: 'scroll',
    whiteSpace: 'nowrap',
    minWidth: 'calc(100vw - 580px)',
    minHeight: 'calc(100vh - 240px)',
    width: 'calc(100vw - 580px)',
    height: 'calc(100vh - 240px)',
    maxWidth: 'calc(100vw - 580px)',
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
});

const stixDomainObjectContentUploadExternalReferenceMutation = graphql`
  mutation StixDomainObjectContentUploadExternalReferenceMutation(
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
      pdfViewerZoom: 1.2,
      markdownSelectedTab: 'write',
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
      const currentFile = R.head(
        R.filter((n) => n.id === currentFileId, files),
      );
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
    this.subscription = SAVE$.subscribe({
      next: () => this.saveFile(),
    });
    this.loadFileContent();
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
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
    SAVE$.next({ action: 'SaveFile' });
  }

  onHtmlFieldChange(content) {
    this.setState({ currentContent: content });
    SAVE$.next({ action: 'SaveFile' });
  }

  onMarkDownFieldChange(value) {
    this.setState({ currentContent: value });
    SAVE$.next({ action: 'SaveFile' });
  }

  onMarkdownChangeTab(tab) {
    this.setState({ markdownSelectedTab: tab });
    SAVE$.next({ action: 'SaveFile' });
  }

  handleDownloadPdf() {
    const { currentFileId, currentContent } = this.state;
    const regex = /<img[^>]+src=(\\?["'])[^'"]+\.gif\1[^>]*\/?>/gi;
    const htmlData = currentContent
      .replaceAll('id="undefined" ', '')
      .replaceAll(regex, '');
    const ret = htmlToPdfmake(htmlData, { imagesByReference: true });
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
      const pdfData = {
        content: ret.content,
        images,
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
      const fragment = currentFileId.split('/');
      const currentName = R.last(fragment);
      pdfMake.createPdf(pdfData, null, fonts).download(`${currentName}.pdf`);
    });
  }

  render() {
    const { classes, stixDomainObject, t } = this.props;
    const {
      currentFileId,
      totalPdfPageNumber,
      isLoading,
      currentContent,
      markdownSelectedTab,
    } = this.state;
    const files = getFiles(stixDomainObject);
    const currentUrl = currentFileId
      && `${APP_BASE_PATH}/storage/view/${encodeURIComponent(currentFileId)}`;
    const currentGetUrl = currentFileId
      && `${APP_BASE_PATH}/storage/get/${encodeURIComponent(currentFileId)}`;
    const currentFile = currentFileId && R.head(R.filter((n) => n.id === currentFileId, files));
    const currentFileType = currentFile && currentFile.metaData.mimetype;
    const { innerHeight } = window;
    const height = innerHeight - 190;
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
          <div>
            <StixDomainObjectContentBar
              directDownload={currentGetUrl}
              handleDownloadPdf={this.handleDownloadPdf.bind(this)}
            />
            <div
              className={classes.editorContainer}
              style={{ minHeight: height }}
            >
              {isLoading ? (
                <Loader variant="inElement" />
              ) : (
                <TextField
                  rows={Math.round(height / 23)}
                  key={currentFile.id}
                  id={currentFile.id}
                  value={currentContent}
                  multiline={true}
                  onBlur={this.saveFile.bind(this)}
                  onChange={this.onTextFieldChange.bind(this)}
                  fullWidth={true}
                />
              )}
            </div>
          </div>
        )}
        {currentFileType === 'text/html' && (
          <div>
            <StixDomainObjectContentBar
              directDownload={currentGetUrl}
              handleDownloadPdf={this.handleDownloadPdf.bind(this)}
            />
            <div
              className={classes.editorContainer}
              style={{ minHeight: height, height }}
            >
              <CKEditor
                editor={Editor}
                config={{
                  width: '100%',
                  language: 'en',
                  image: {
                    resizeUnit: 'px',
                  },
                }}
                data={currentContent}
                onChange={(event, editor) => {
                  this.onHtmlFieldChange(editor.getData());
                }}
                onBlur={this.saveFile.bind(this)}
              />
            </div>
          </div>
        )}
        {currentFileType === 'text/markdown' && (
          <div>
            <StixDomainObjectContentBar
              directDownload={currentGetUrl}
              handleDownloadPdf={this.handleDownloadPdf.bind(this)}
            />
            <div
              className={classes.editorContainer}
              style={{ minHeight: height, height }}
              onBlur={this.saveFile.bind(this)}
            >
              {isLoading ? (
                <Loader variant="inElement" />
              ) : (
                <ReactMde
                  value={currentContent}
                  minEditorHeight={height - 80}
                  maxEditorHeight={height - 80}
                  onChange={this.onMarkDownFieldChange.bind(this)}
                  selectedTab={markdownSelectedTab}
                  onTabChange={this.onMarkdownChangeTab.bind(this)}
                  generateMarkdownPreview={(markdown) => Promise.resolve(
                      <Markdown
                        remarkPlugins={[remarkGfm, remarkParse]}
                        parserOptions={{ commonmark: true }}
                      >
                        {markdown}
                      </Markdown>,
                  )
                  }
                  l18n={{
                    write: t('Write'),
                    preview: t('Preview'),
                    uploadingImage: t('Uploading image'),
                    pasteDropSelect: t('Paste'),
                  }}
                />
              )}
            </div>
          </div>
        )}
        {currentFileType === 'application/pdf' && (
          <div>
            <StixDomainObjectContentBar
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
                    style={{ position: 'absolute', top: '50%', left: '50%' }}
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
