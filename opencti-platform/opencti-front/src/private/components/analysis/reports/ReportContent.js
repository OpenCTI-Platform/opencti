import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import inject18n from '../../../../components/i18n';
import ReportContentFiles, {
  reportContentFilesRefetchQuery,
} from './ReportContentFiles';
import { QueryRenderer } from '../../../../relay/environment';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: '20px 0 0 0',
    padding: '0 260px 90px 0',
  },
  documentContainer: {
    margin: '15px 0 0 0',
    minWidth: 'calc(100vw - 500px)',
    minHeight: 'calc(100vh - 300px)',
    width: 'calc(100vw - 500px)',
    height: 'calc(100vh - 180px)',
    maxWidth: 'calc(100vw - 500px)',
    maxHeight: 'calc(100vh - 180px)',
    display: 'flex',
    justifyContent: 'center',
    position: 'relative',
    overflow: 'hidden',
  },
});

class ReportContentComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      currentFile: null,
    };
  }

  handleSelectFile(file) {
    this.setState({ currentFile: file });
  }

  render() {
    const { classes, t, report } = this.props;
    const { currentFile } = this.state;
    const currentUrl = currentFile && `/storage/view/${currentFile.id}`;
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
        <div className={classes.documentContainer}>
          {currentFile ? (
            <embed
              src={currentUrl}
              width="100%"
              height="100%"
              type="application/pdf"
              style={{ width: '100%', height: '100%' }}
            />
          ) : (
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
          )}
        </div>
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
