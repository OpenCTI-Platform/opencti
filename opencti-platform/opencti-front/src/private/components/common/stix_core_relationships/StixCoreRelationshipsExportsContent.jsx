import List from '@mui/material/List';
import Slide from '@mui/material/Slide';
import withStyles from '@mui/styles/withStyles';
import * as PropTypes from 'prop-types';
import { compose, pathOr, uniq, flatten, map } from 'ramda';
import React, { Component } from 'react';
import { createRefetchContainer, graphql } from 'react-relay';
import { interval } from 'rxjs';
import inject18n from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { KNOWLEDGE_KNGETEXPORT_KNASKEXPORT } from '../../../../utils/hooks/useGranted';
import FileLine from '../files/FileLine';
import StixCoreRelationshipsExportCreation, { scopesConn } from './StixCoreRelationshipsExportCreation';
import { Stack, Tooltip } from '@mui/material';
import Button from '@common/button/Button';

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
  constructor(props) {
    super(props);
    this.state = {
      open: false,
    };
  }

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

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  render() {
    const {
      t,
      data,
      exportContext,
      paginationOptions,
    } = this.props;
    const stixCoreRelationshipsExportFiles = pathOr(
      [],
      ['stixCoreRelationshipsExportFiles', 'edges'],
      data,
    );

    const connectorsExport = data?.connectorsForExport ?? [];
    const exportScopes = uniq(
      flatten(map((c) => c.connector_scope, connectorsExport)),
    );
    const exportConnsPerFormat = scopesConn(connectorsExport);

    const isExportActive = (format) => exportConnsPerFormat[format].filter((x) => x.data.active).length > 0;
    const isExportPossible = exportScopes.filter((x) => isExportActive(x)).length > 0;

    return (
      <Stack gap={2}>
        <Stack
          direction="row"
          justifyContent="flex-end"
          gap={1}
        >
          <Tooltip
            title={
              isExportPossible
                ? t('Generate an export')
                : t('No export connector available to generate an export')
            }
            aria-label="generate-export"
          >
            <Button
              onClick={this.handleOpen.bind(this)}
              disabled={!isExportPossible}
            >
              {t('Generate an export')}
            </Button>
          </Tooltip>
        </Stack>

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
            open={this.state.open}
            onClose={this.handleClose.bind(this)}
          />
        </Security>
      </Stack>
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
        connectorsForExport {
          id
          name
          active
          connector_scope
          updated_at
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

  open: PropTypes.bool,
  setOpen: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipsExportsContent);
