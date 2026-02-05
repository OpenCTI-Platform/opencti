import List from '@mui/material/List';
import Slide from '@mui/material/Slide';
import withStyles from '@mui/styles/withStyles';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import React, { Component } from 'react';
import { createRefetchContainer, graphql } from 'react-relay';
import { interval } from 'rxjs';
import inject18n from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { KNOWLEDGE_KNGETEXPORT_KNASKEXPORT } from '../../../../utils/hooks/useGranted';
import FileLine from '../../common/files/FileLine';
import StixCyberObservablesExportCreation from './StixCyberObservablesExportCreation';

const interval$ = interval(FIVE_SECONDS);

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  listIcon: {
    marginRight: 0,
  },
  item: {
    padding: '0 0 0 10px',
  },
  itemField: {
    padding: '0 15px 0 15px',
  },
  toolbar: theme.mixins.toolbar,
});

class StixCyberObservablesExportsContentComponent extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      if (this.props.isOpen) {
        this.props.relay.refetch({ count: 25, exportContext: this.props.exportContext });
      }
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  render() {
    const { t, data, paginationOptions, exportContext } = this.props;
    const stixCyberObservablesExportFiles = pathOr(
      [],
      ['stixCyberObservablesExportFiles', 'edges'],
      data,
    );
    return (
      <div>
        <List>
          {stixCyberObservablesExportFiles.length > 0 ? (
            stixCyberObservablesExportFiles.map((file) => file?.node && (
              <FileLine
                key={file.node.id}
                file={file.node}
                dense={true}
                disableImport={true}
                directDownload={true}
              />
            ))
          ) : (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                {t('No file for the moment')}
              </span>
            </div>
          )}
        </List>
        <Security needs={[KNOWLEDGE_KNGETEXPORT_KNASKEXPORT]}>
          <StixCyberObservablesExportCreation
            data={data}
            paginationOptions={paginationOptions}
            exportContext={exportContext}
            onExportAsk={() => this.props.relay.refetch({ count: 25, exportContext: this.props.exportContext })}
          />
        </Security>
      </div>
    );
  }
}

export const stixCyberObservablesExportsContentQuery = graphql`
  query StixCyberObservablesExportsContentRefetchQuery($count: Int!, $exportContext: ExportContext!) {
    ...StixCyberObservablesExportsContent_data @arguments(count: $count, exportContext: $exportContext)
  }
`;

const StixCyberObservablesExportsContent = createRefetchContainer(
  StixCyberObservablesExportsContentComponent,
  {
    data: graphql`
      fragment StixCyberObservablesExportsContent_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        exportContext: { type: "ExportContext!" }
      ) {
        stixCyberObservablesExportFiles(first: $count, exportContext: $exportContext)
          @connection(key: "Pagination_stixCyberObservablesExportFiles") {
          edges {
            node {
              id
              ...FileLine_file
            }
          }
        }
        ...StixCyberObservablesExportCreation_data
      }
    `,
  },
  stixCyberObservablesExportsContentQuery,
);

StixCyberObservablesExportsContent.propTypes = {
  t: PropTypes.func,
  data: PropTypes.object,
  paginationOptions: PropTypes.object,
  handleApplyListArgs: PropTypes.func,
  isOpen: PropTypes.bool,
  exportContext: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCyberObservablesExportsContent);
