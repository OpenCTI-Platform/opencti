import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import Axios from 'axios';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import Box from '@mui/material/Box';
import TextField from '@mui/material/TextField';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Paper from '@mui/material/Paper';
import inject18n from '../../../../components/i18n';
import ReportContentFiles, {
  reportContentFilesRefetchQuery,
} from './ReportContentFiles';
import {
  // APP_BASE_PATH,
  commitMutation,
  fetchQuery,
  QueryRenderer,
} from '../../../../relay/environment';
import Loader from '../../../../components/Loader';
import { stixDomainObjectsLinesSearchQuery } from '../../common/stix_domain_objects/StixDomainObjectsLines';
import { defaultValue, graphRawImages } from '../../../../utils/Graph';
import { resolveLink } from '../../../../utils/Entity';
// import 'react-pdf/dist/esm/Page/AnnotationLayer.css';
import ReportContentPdfBar from './ReportContentPdfBar';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import { truncate } from '../../../../utils/String';

// pdfjs.GlobalWorkerOptions.workerSrc = `${APP_BASE_PATH}/static/pdf.worker.js`;

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: '20px 0 0 0',
    padding: '0 260px 90px 0',
  },
  tabs: {
    position: 'absolute',
    right: 0,
    height: '100%',
  },
  editorContainer: {
    height: '100%',
    minHeight: '100%',
    margin: '20px 0 0 0',
    padding: '15px 30px 15px 30px',
    borderRadius: 6,
  },
  documentContainer: {
    margin: '15px 0 -24px 0',
    overflow: 'scroll',
    whiteSpace: 'nowrap',
    minWidth: 'calc(100vw - 500px)',
    minHeight: 'calc(100vh - 300px)',
    width: 'calc(100vw - 500px)',
    height: 'calc(100vh - 300px)',
    maxWidth: 'calc(100vw - 500px)',
    maxHeight: 'calc(100vh - 300px)',
    display: 'flex',
    justifyContent: 'center',
    position: 'relative',
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

const reportContentUploadStixDomainObjectMutation = graphql`
  mutation ReportContentUploadStixDomainObjectMutation(
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

const reportContentUploadExternalReferenceMutation = graphql`
  mutation ReportContentUploadExternalReferenceMutation(
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

class ReportContentComponent extends Component {
  constructor(props) {
    super(props);
    this.editorRef = React.createRef();
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-report-content-${props.report.id}`,
    );
    this.state = {
      currentTab: R.propOr(0, 'currentTab', params),
      currentFile: R.propOr(
        {
          id: `import/Report/${props.report.id}/Main.html`,
          name: 'Main.html',
          metaData: {
            mimetype: 'text/html',
          },
        },
        'currentFile',
        params,
      ),
      initialContent: props.t('Write something awesome...'),
      currentContent: props.t('Write something awesome...'),
      currentHtmlContent: null,
      currentBase64Content: null,
      totalPdfPageNumber: null,
      currentPdfPageNumber: 1,
      pdfViewerZoom: 2,
      mentions: [],
      mentionKeyword: '',
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-report-content-${this.props.report.id}`,
      this.state,
    );
  }

  onDocumentLoadSuccess({ numPages: nextNumPages }) {
    this.setState({ totalPdfPageNumber: nextNumPages });
  }

  setSunEditorInstance(editor) {
    this.editorRef.current = editor;
  }

  loadFileContent() {
    const convertToHtmlPdf = this.state.currentTab === 2
      && this.state.currentFile.metaData.mimetype === 'text/markdown';
    this.setState({ isLoading: true }, () => {
      const url = `/storage/${convertToHtmlPdf ? 'html' : 'view'}/${
        this.state.currentFile.id
      }`;
      Axios.get(url).then((res) => {
        const content = res.data;
        this.setState({
          initialContent: content,
          currentContent: content,
          isLoading: false,
        });
      });
    });
  }

  componentDidMount() {
    this.loadFileContent();
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

  saveFile() {
    const { currentId, isExternalReference, file } = this.prepareSaveFile();
    commitMutation({
      mutation: isExternalReference
        ? reportContentUploadExternalReferenceMutation
        : reportContentUploadStixDomainObjectMutation,
      variables: { file, id: currentId },
    });
  }

  saveFileAndSelectFile(newFile) {
    this.setState({ isLoading: true }, () => {
      const { currentId, isExternalReference, file } = this.prepareSaveFile();
      commitMutation({
        mutation: isExternalReference
          ? reportContentUploadExternalReferenceMutation
          : reportContentUploadStixDomainObjectMutation,
        variables: { file, id: currentId },
        onCompleted: () => {
          const isPdf = newFile.metaData.mimetype === 'application/pdf';
          this.setState(
            {
              currentFile: newFile,
              currentTab: isPdf ? 2 : 0,
              isLoading: !isPdf,
            },
            () => {
              this.saveView();
              if (!isPdf) {
                this.loadFileContent();
              }
            },
          );
        },
      });
    });
  }

  handleSelectFile(file) {
    this.setState({ currentBase64Content: null }, () => {
      if (this.state.currentTab === 0 || this.state.currentTab === 1) {
        this.saveFileAndSelectFile(file);
      } else {
        const isPdf = file.metaData.mimetype === 'application/pdf';
        this.setState(
          {
            currentFile: file,
            currentTab: isPdf ? 2 : 0,
            isLoading: !isPdf,
          },
          () => {
            this.saveView();
            if (!isPdf) {
              this.loadFileContent();
            }
          },
        );
      }
    });
  }

  saveFileAndChangeTab(value) {
    const { currentFile } = this.state;
    this.setState({ isLoading: true }, () => {
      const { currentId, isExternalReference, file } = this.prepareSaveFile();
      commitMutation({
        mutation: isExternalReference
          ? reportContentUploadExternalReferenceMutation
          : reportContentUploadStixDomainObjectMutation,
        variables: {
          file,
          id: currentId,
        },
        onCompleted: () => {
          this.setState(
            {
              currentTab: value,
              initialContent: this.state.currentContent,
              isLoading: false,
            },
            () => {
              this.saveView();
              if (
                currentFile.metaData.mimetype === 'text/markdown'
                || currentFile.metaData.mimetype === 'text/html'
              ) {
                this.loadFileContent();
              }
            },
          );
        },
      });
    });
  }

  handleChangeTab(event, value) {
    if (this.state.currentTab === 0 || this.state.currentTab === 1) {
      this.saveFileAndChangeTab(value);
    } else if (this.state.currentTab === 2) {
      this.setState({ currentBase64Content: null, currentTab: value }, () => this.saveView());
    } else {
      this.setState({ currentTab: value }, () => this.saveView());
    }
  }

  onEditorChange(value) {
    this.setState({ currentContent: value() });
  }

  onTextFieldChange(event) {
    this.setState({ currentContent: event.target.value });
  }

  onHtmlEditorChange(value) {
    this.setState({ currentContent: value });
  }

  handleZoomIn() {
    this.setState({ pdfViewerZoom: this.state.pdfViewerZoom + 0.2 }, () => this.saveView());
  }

  handleZoomOut() {
    this.setState({ pdfViewerZoom: this.state.pdfViewerZoom - 0.2 }, () => this.saveView());
  }

  handleMentionFilter({ value: mentionKeyword }) {
    if (mentionKeyword && mentionKeyword.length > 0) {
      fetchQuery(stixDomainObjectsLinesSearchQuery, {
        search: `"${mentionKeyword}"`,
        count: 10,
      })
        .toPromise()
        .then((data) => {
          const mentions = R.pipe(
            R.map((n) => n.node),
            R.map((n) => ({
              id: n.id,
              name: defaultValue(n),
              link: `${resolveLink(n.entity_type)}/${n.id}`,
              avatar: graphRawImages[n.entity_type],
            })),
          )(R.pathOr([], ['stixDomainObjects', 'edges'], data));
          this.setState({ mentions });
        });
    } else {
      this.setState({ mentions: [] });
    }
  }

  render() {
    const { classes, t, report } = this.props;
    const {
      isLoading,
      currentTab,
      initialContent,
      currentContent,
      currentFile,
      currentBase64Content,
      // totalPdfPageNumber,
    } = this.state;
    const currentTitle = R.last(currentFile.id.split('/'));
    const currentUrl = `/storage/view/${currentFile.id}`;
    const currentGetUrl = `/storage/get/${currentFile.id}`;
    const isFilePdf = currentFile.metaData.mimetype === 'application/pdf';
    const isFileHtml = currentFile.metaData.mimetype === 'text/html';
    const isReadOnly = isFilePdf;
    const { innerHeight } = window;
    const height = innerHeight - 250;
    return (
      <div className={classes.container}>
        <QueryRenderer
          query={reportContentFilesRefetchQuery}
          variables={{ id: report.id }}
          render={({ props }) => {
            if (props && props.report) {
              return (
                <ReportContentFiles
                  report={props.report}
                  handleSelectFile={this.handleSelectFile.bind(this)}
                  currentFile={currentFile}
                />
              );
            }
            return <div />;
          }}
        />
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <span style={{ fontSize: 14, color: 'inherit', fontWeight: 400 }}>
            {truncate(currentTitle, 100)}
          </span>
          <Tabs
            value={currentTab}
            onChange={this.handleChangeTab.bind(this)}
            className={classes.tabs}
          >
            <Tab label={t('Rich editor')} disabled={isFilePdf} />
            <Tab
              label={t('Markdown source')}
              disabled={isFilePdf || isFileHtml}
            />
            <Tab label={t('PDF viewer')} />
          </Tabs>
        </Box>
        {this.state.currentTab === 0 && !isFileHtml && (
          <Paper
            classes={{ root: classes.editorContainer }}
            variant="outlined"
            style={{ minHeight: height, fontSize: '120%' }}
          >
            {isLoading ? <Loader variant="inElement" /> : <div />}
          </Paper>
        )}
        {this.state.currentTab === 0 && isFileHtml && (
          <Paper
            classes={{ root: classes.editorContainer }}
            variant="outlined"
            style={{ minHeight: height, fontSize: '120%' }}
          >
            {isLoading ? (
              <Loader variant="inElement" />
            ) : (
              <div style={{ height: '100%' }}>
                <div />
              </div>
            )}
          </Paper>
        )}
        {this.state.currentTab === 1 && (
          <Paper
            classes={{ root: classes.editorContainer }}
            variant="outlined"
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
                InputProps={{
                  readOnly: isReadOnly,
                }}
                multiline={true}
                onBlur={!isReadOnly && this.saveFile.bind(this)}
                onChange={!isReadOnly && this.onTextFieldChange.bind(this)}
                fullWidth={true}
              />
            )}
          </Paper>
        )}
        {this.state.currentTab === 2 && isFilePdf && (
          <div style={{ marginTop: 20 }}>
            <ReportContentPdfBar
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
              ></Document>
            </div>
          </div>
        )}
        {this.state.currentTab === 2
          && (currentFile.metaData.mimetype === 'text/html'
            || currentFile.metaData.mimetype === 'text/markdown')
          && currentBase64Content && (
            <div style={{ marginTop: 20 }}>
              <ReportContentPdfBar
                handleZoomIn={this.handleZoomIn.bind(this)}
                handleZoomOut={this.handleZoomOut.bind(this)}
                currentZoom={this.state.pdfViewerZoom}
              />
              <div className={classes.documentContainer}>
                <Document
                  className={classes.pdfViewer}
                  onLoadSuccess={this.onDocumentLoadSuccess.bind(this)}
                  loading={<Loader variant="inElement" />}
                  file={currentBase64Content}
                ></Document>
              </div>
            </div>
        )}
      </div>
    );
  }
}

ReportContentComponent.propTypes = {
  report: PropTypes.object,
  theme: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ReportContent = createFragmentContainer(ReportContentComponent, {
  report: graphql`
    fragment ReportContent_report on Report {
      id
    }
  `,
});

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(ReportContent);
