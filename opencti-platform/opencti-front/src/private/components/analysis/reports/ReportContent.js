import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import Axios from 'axios';
import Editor from 'rich-markdown-editor';
import { light, dark } from 'rich-markdown-editor/dist/theme';
import SunEditor from 'suneditor-react';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles, withTheme } from '@material-ui/core/styles';
import AppBar from '@material-ui/core/AppBar';
import Toolbar from '@material-ui/core/Toolbar';
import TextField from '@material-ui/core/TextField';
import Tabs from '@material-ui/core/Tabs';
import Tab from '@material-ui/core/Tab';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import ReportContentFiles, {
  reportContentFilesRefetchQuery,
} from './ReportContentFiles';
import {
  commitMutation,
  fetchQuery,
  QueryRenderer,
} from '../../../../relay/environment';
import Loader from '../../../../components/Loader';
import { stixDomainObjectsLinesSearchQuery } from '../../common/stix_domain_objects/StixDomainObjectsLines';
import { defaultValue, graphRawImages } from '../../../../utils/Graph';
import { resolveLink } from '../../../../utils/Entity';

const styles = (theme) => ({
  container: {
    width: '100%',
    height: '100%',
    margin: '20px 0 0 0',
    padding: '0 260px 90px 0',
  },
  appBar: {
    width: '100%',
    height: 50,
    zIndex: theme.zIndex.drawer + 1,
    backgroundColor: theme.palette.navAlt.background,
    color: theme.palette.text.primary,
    borderBottom: '1px solid #5c5c5c',
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
    this.state = {
      isLoading: true,
      currentTab: 0,
      currentFile: {
        id: `import/Report/${props.report.id}/Main.html`,
        name: 'Main.html',
        metaData: {
          mimetype: 'text/html',
        },
      },
      initialContent: props.t('Write something awesome...'),
      currentContent: props.t('Write something awesome...'),
      mentions: [],
      mentionKeyword: '',
    };
  }

  setSunEditorInstance(editor) {
    this.editorRef.current = editor;
  }

  loadFileContent() {
    this.setState({ isLoading: true }, () => {
      const url = `/storage/view/${this.state.currentFile.id}`;
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

  componentWillMount() {
    if (this.props.theme.palette.type === 'dark') {
      // eslint-disable-next-line global-require
      require('../../../../resources/css/suneditor-dark.css');
      // eslint-disable-next-line global-require
      require('../../../../resources/css/suneditor-dark-contents.css');
    } else {
      // eslint-disable-next-line global-require
      require('../../../../resources/css/suneditor-light.css');
      // eslint-disable-next-line global-require
      require('../../../../resources/css/suneditor-light-contents.css');
    }
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
            () => !isPdf && this.loadFileContent(),
          );
        },
      });
    });
  }

  handleSelectFile(file) {
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
        () => !isPdf && this.loadFileContent(),
      );
    }
  }

  saveFileAndChangeTab(value) {
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
          this.setState({
            currentTab: value,
            initialContent: this.state.currentContent,
            isLoading: false,
          });
        },
      });
    });
  }

  handleChangeTab(event, value) {
    if (this.state.currentTab === 0 || this.state.currentTab === 1) {
      this.saveFileAndChangeTab(value);
    } else {
      this.setState({ currentTab: value });
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
    const {
      classes, theme, t, report,
    } = this.props;
    const {
      isLoading,
      currentTab,
      initialContent,
      currentContent,
      currentFile,
    } = this.state;
    const currentTitle = R.last(currentFile.id.split('/'));
    const currentUrl = `/storage/view/${currentFile.id}`;
    const currentPdfUrl = `/storage/pdf/${currentFile.id}`;
    const isFilePdf = currentFile.metaData.mimetype === 'application/pdf';
    const isFileHtml = currentFile.metaData.mimetype === 'text/html';
    const isReadOnly = isFilePdf;
    const customTheme = {
      fontFamily: 'Roboto',
      zIndex: 5000,
      background: theme.palette.background.paper,
    };
    const editorTheme = theme.palette.type === 'dark'
      ? { ...dark, ...customTheme }
      : { ...light, ...customTheme };
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
        <AppBar position="static" elevation={0} className={classes.appBar}>
          <Toolbar style={{ minHeight: 50 }}>
            <span style={{ fontSize: 18, color: 'inherit', fontWeight: 400 }}>
              {currentTitle}
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
          </Toolbar>
        </AppBar>
        {this.state.currentTab === 0 && !isFileHtml && (
          <Paper
            classes={{ root: classes.editorContainer }}
            elevation={2}
            style={{ minHeight: height, fontSize: '120%' }}
          >
            {isLoading ? (
              <Loader variant="inElement" />
            ) : (
              <Editor
                key={currentFile.id}
                id={currentFile.id}
                value={initialContent}
                dark={theme.palette.type === 'dark'}
                theme={editorTheme}
                readOnly={isReadOnly}
                onBlur={!isReadOnly && this.saveFile.bind(this)}
                onChange={!isReadOnly && this.onEditorChange.bind(this)}
              />
            )}
          </Paper>
        )}
        {this.state.currentTab === 0 && isFileHtml && (
          <Paper
            classes={{ root: classes.editorContainer }}
            elevation={2}
            style={{ minHeight: height, fontSize: '120%' }}
          >
            {isLoading ? (
              <Loader variant="inElement" />
            ) : (
              <div style={{ height: '100%' }}>
                <SunEditor
                  getSunEditorInstance={this.setSunEditorInstance.bind(this)}
                  defaultValue={initialContent}
                  height="100%"
                  setOptions={{
                    buttonList: [
                      ['undo', 'redo', 'font', 'fontSize', 'formatBlock'],
                      [
                        'bold',
                        'underline',
                        'italic',
                        'strike',
                        'subscript',
                        'superscript',
                        'removeFormat',
                      ],
                      [
                        'fontColor',
                        'hiliteColor',
                        'outdent',
                        'indent',
                        'align',
                        'horizontalRule',
                        'list',
                        'table',
                      ],
                      ['link', 'image', 'video', 'showBlocks', 'preview'],
                    ],
                  }}
                  onChange={this.onHtmlEditorChange.bind(this)}
                  onBlur={this.saveFile.bind(this)}
                />
              </div>
            )}
          </Paper>
        )}
        {this.state.currentTab === 1 && (
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
            <embed src={currentUrl} width="100%" height={height} />
          </div>
        )}
        {this.state.currentTab === 2 && !isFilePdf && (
          <div style={{ marginTop: 20 }}>
            <embed src={currentPdfUrl} width="100%" height={height} />
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
