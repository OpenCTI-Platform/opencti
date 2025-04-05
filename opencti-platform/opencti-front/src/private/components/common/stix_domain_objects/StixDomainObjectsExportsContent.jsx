import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import Slide from '@mui/material/Slide';
import { createRefetchContainer, graphql } from 'react-relay';
import List from '@mui/material/List';
import { interval } from 'rxjs';
import StixDomainObjectsExportCreation from './StixDomainObjectsExportCreation';
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

class StixDomainObjectsExportsContentComponent extends Component {
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
    const { t, data, exportContext, paginationOptions } = this.props;
    const stixDomainObjectsExportFiles = data?.stixDomainObjectsExportFiles?.edges ?? [];

    // Extract pattern types from indicators
    const indicators = data?.indicators?.edges ?? [];
    const idAndPatternTypes = indicators.map((indicator) => ({
      id: indicator.node.id,
      pattern_type: indicator.node.pattern_type,
    }));

    return (
      <>
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
            idAndPatternTypes={idAndPatternTypes}
            onExportAsk={() => this.props.relay.refetch({ count: 25, exportContext: this.props.exportContext })}
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
    $filters: FilterGroup!
  ) {
    ...StixDomainObjectsExportsContent_data
      @arguments(count: $count, exportContext: $exportContext, filters: $filters )
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
        filters: { type: "FilterGroup" }
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
        indicators(filters: $filters) {
          edges {
            node {
              id
              pattern_type
            }
          }
        }
        ...StixDomainObjectsExportCreation_data
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
