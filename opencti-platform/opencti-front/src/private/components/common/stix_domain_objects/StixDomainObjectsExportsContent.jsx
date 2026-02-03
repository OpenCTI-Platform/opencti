import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter, flatten, map, uniq } from 'ramda';
import Slide from '@mui/material/Slide';
import { createRefetchContainer, graphql } from 'react-relay';
import List from '@mui/material/List';
import { interval } from 'rxjs';
import StixDomainObjectsExportCreation, { scopesConn } from './StixDomainObjectsExportCreation';
import { FIVE_SECONDS } from '../../../../utils/Time';
import FileLine from '../files/FileLine';
import inject18n from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNGETEXPORT_KNASKEXPORT } from '../../../../utils/hooks/useGranted';
import Button from '@common/button/Button';
import Tooltip from '@mui/material/Tooltip';
import { Stack } from '@mui/material';

const interval$ = interval(FIVE_SECONDS);

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class StixDomainObjectsExportsContentComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

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

  handleOpen = () => {
    this.setState({ open: true });
  };

  handleClose = () => {
    this.setState({ open: false });
  };

  render() {
    const { t, data, exportContext, paginationOptions } = this.props;
    const stixDomainObjectsExportFiles = data?.stixDomainObjectsExportFiles?.edges ?? [];

    const connectorsExport = data?.connectorsForExport ?? [];
    const exportScopes = uniq(
      flatten(map((c) => c.connector_scope, connectorsExport)),
    );
    const exportConnsPerFormat = scopesConn(connectorsExport);
    const isExportActive = (format) => filter((x) => x.data.active, exportConnsPerFormat[format]).length > 0;
    const isExportPossible = filter((x) => isExportActive(x), exportScopes).length > 0;

    return (
      <>
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
              color="secondary"
              disabled={!isExportPossible}
            >
              {t('Generate an export')}
            </Button>
          </Tooltip>
        </Stack>
        <List>
          {stixDomainObjectsExportFiles.length > 0 ? (
            stixDomainObjectsExportFiles.map(
              (file) => file?.node && (
                <FileLine
                  key={file.node.id}
                  file={file.node}
                  dense={true}
                  disableImport={true}
                  directDownload={true}
                />
              ),
            )
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
          <StixDomainObjectsExportCreation
            data={data}
            exportContext={exportContext}
            paginationOptions={paginationOptions}
            open={this.state.open}
            onClose={this.handleClose}
            onExportAsk={() => this.props.relay.refetch({ count: 25, exportContext: this.props.exportContext })}
            exportScopes={exportScopes}
            isExportActive={isExportActive}
          />
        </Security>
      </>
    );
  }
}

export const stixDomainObjectsExportsContentQuery = graphql`
  query StixDomainObjectsExportsContentRefetchQuery(
    $count: Int!
    $exportContext: ExportContext!
  ) {
    ...StixDomainObjectsExportsContent_data
      @arguments(count: $count, exportContext: $exportContext)
  }
`;

const StixDomainObjectsExportsContent = createRefetchContainer(
  StixDomainObjectsExportsContentComponent,
  {
    data: graphql`
      fragment StixDomainObjectsExportsContent_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        exportContext: { type: "ExportContext!" }
      ) {
        stixDomainObjectsExportFiles(first: $count, exportContext: $exportContext)
          @connection(key: "Pagination_stixDomainObjectsExportFiles") {
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
      }
    `,
  },
  stixDomainObjectsExportsContentQuery,
);

StixDomainObjectsExportsContent.propTypes = {
  classes: PropTypes.object.isRequired,
  t: PropTypes.func,
  handleToggle: PropTypes.func,
  data: PropTypes.object,
  exportContext: PropTypes.object,
  paginationOptions: PropTypes.object,
  handleApplyListArgs: PropTypes.func,
  isOpen: PropTypes.bool,
};

export default compose(inject18n)(StixDomainObjectsExportsContent);
