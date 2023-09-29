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
        this.props.relay.refetch({
          type: this.props.exportEntityType,
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
      t,
      data,
      exportEntityType,
      paginationOptions,
      context,
    } = this.props;
    const stixDomainObjectsExportFiles = data?.stixDomainObjectsExportFiles?.edges ?? [];
    let paginationOptionsForExport = paginationOptions; // paginationsOptions with correct elementId
    if (paginationOptions?.fromId) {
      // for relationships contained in entity>Knowledge>Sightings
      const filtersForExport = [
        ...paginationOptionsForExport.filters,
        { key: 'fromId', values: [paginationOptions.fromId] },
      ];
      paginationOptionsForExport = {
        ...paginationOptions,
        filters: filtersForExport,
      };
    }
    return (
      <div>
        <List>
          {stixDomainObjectsExportFiles.length > 0 ? (
            stixDomainObjectsExportFiles.map((file) => file?.node && (
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
          <StixDomainObjectsExportCreation
            data={data}
            exportEntityType={exportEntityType}
            paginationOptions={paginationOptionsForExport}
            context={context}
            onExportAsk={() => this.props.relay.refetch({
              type: this.props.exportEntityType,
              count: 25,
            })
            }
          />
        </Security>
      </div>
    );
  }
}

export const stixDomainObjectsExportsContentQuery = graphql`
  query StixDomainObjectsExportsContentRefetchQuery(
    $count: Int!
    $type: String!
  ) {
    ...StixDomainObjectsExportsContent_data
      @arguments(count: $count, type: $type)
  }
`;

const StixDomainObjectsExportsContent = createRefetchContainer(
  StixDomainObjectsExportsContentComponent,
  {
    data: graphql`
      fragment StixDomainObjectsExportsContent_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        type: { type: "String!" }
      ) {
        stixDomainObjectsExportFiles(first: $count, type: $type)
          @connection(key: "Pagination_stixDomainObjectsExportFiles") {
          edges {
            node {
              id
              ...FileLine_file
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
  exportEntityType: PropTypes.string.isRequired,
  paginationOptions: PropTypes.object,
  handleApplyListArgs: PropTypes.func,
  isOpen: PropTypes.bool,
  context: PropTypes.string,
};

export default compose(
  inject18n,
)(StixDomainObjectsExportsContent);
