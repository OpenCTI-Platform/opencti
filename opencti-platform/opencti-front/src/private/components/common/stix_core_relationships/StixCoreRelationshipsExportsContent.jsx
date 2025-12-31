import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Slide from '@mui/material/Slide';
import { graphql, createRefetchContainer } from 'react-relay';
import List from '@mui/material/List';
import { interval } from 'rxjs';
import IconButton from '@common/button/IconButton';
import { Close } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import StixCoreRelationshipsExportCreation from './StixCoreRelationshipsExportCreation';
import { FIVE_SECONDS } from '../../../../utils/Time';
import FileLine from '../files/FileLine';
import inject18n from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNGETEXPORT_KNASKEXPORT } from '../../../../utils/hooks/useGranted';

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
});

class StixCoreRelationshipsExportsContentComponent extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      if (this.props.isOpen) {
        this.props.relay.refetch({
          exportContext: this.props.exportContext,
          count: 25,
        });
      }
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  render() {
    const {
      classes,
      t,
      data,
      exportContext,
      paginationOptions,
      handleToggle,
    } = this.props;
    const stixCoreRelationshipsExportFiles = pathOr(
      [],
      ['stixCoreRelationshipsExportFiles', 'edges'],
      data,
    );
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleToggle.bind(this)}
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Exports list')}</Typography>
        </div>
        <List>
          {stixCoreRelationshipsExportFiles.length > 0 ? (
            stixCoreRelationshipsExportFiles.map((file) => file?.node && (
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
          <StixCoreRelationshipsExportCreation
            data={data}
            exportContext={exportContext}
            paginationOptions={paginationOptions}
            onExportAsk={() => this.props.relay.refetch({ count: 25, exportContext: this.props.exportContext })}
          />
        </Security>
      </div>
    );
  }
}

export const stixCoreRelationshipsExportsContentQuery = graphql`
  query StixCoreRelationshipsExportsContentRefetchQuery(
    $count: Int!
    $exportContext: ExportContext!
  ) {
    ...StixCoreRelationshipsExportsContent_data
      @arguments(count: $count, exportContext: $exportContext)
  }
`;

const StixCoreRelationshipsExportsContent = createRefetchContainer(
  StixCoreRelationshipsExportsContentComponent,
  {
    data: graphql`
      fragment StixCoreRelationshipsExportsContent_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        exportContext: { type: "ExportContext!" }
      ) {
        stixCoreRelationshipsExportFiles(first: $count, exportContext: $exportContext)
          @connection(key: "Pagination_stixCoreRelationshipsExportFiles") {
          edges {
            node {
              id
              ...FileLine_file
            }
          }
        }
        ...StixCoreRelationshipsExportCreation_data
      }
    `,
  },
  stixCoreRelationshipsExportsContentQuery,
);

StixCoreRelationshipsExportsContent.propTypes = {
  classes: PropTypes.object.isRequired,
  t: PropTypes.func,
  handleToggle: PropTypes.func,
  data: PropTypes.object,
  exportContext: PropTypes.object,
  paginationOptions: PropTypes.object,
  handleApplyListArgs: PropTypes.func,
  isOpen: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipsExportsContent);
