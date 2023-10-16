import React, { useEffect } from 'react';
import { createRefetchContainer, graphql } from 'react-relay';
import List from '@mui/material/List';
import { interval } from 'rxjs';
import StixCoreObjectsExportCreation from './StixCoreObjectsExportCreation';
import { FIVE_SECONDS } from '../../../../utils/Time';
import FileLine from '../files/FileLine';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNGETEXPORT_KNASKEXPORT } from '../../../../utils/hooks/useGranted';
import { useFormatter } from '../../../../components/i18n';

const interval$ = interval(FIVE_SECONDS);

const StixCoreObjectsExportsContentComponent = ({
  relay,
  isOpen,
  data,
  exportEntityType,
  paginationOptions,
  context,
}) => {
  const { t } = useFormatter();
  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      if (isOpen) {
        relay.refetch({
          type: exportEntityType,
          count: 25,
        });
      }
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  });
  const stixCoreObjectsExportFiles = data?.stixCoreObjectsExportFiles?.edges ?? [];
  let paginationOptionsForExport = paginationOptions; // paginationsOptions with correct types filters
  if (paginationOptions?.types && paginationOptions.types.length > 0) {
    const filtersForExport = [
      ...paginationOptionsForExport.filters,
      { key: 'entity_type', values: paginationOptions.types },
    ];
    paginationOptionsForExport = {
      ...paginationOptions,
      filters: filtersForExport,
    };
  }
  return (
    <div>
      <List>
        {stixCoreObjectsExportFiles.length > 0 ? (
          stixCoreObjectsExportFiles.map((file) => file?.node && (
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
        <StixCoreObjectsExportCreation
          data={data}
          exportEntityType={exportEntityType}
          paginationOptions={paginationOptionsForExport}
          context={context}
          onExportAsk={() => relay.refetch({
            type: exportEntityType,
            count: 25,
          })
          }
        />
      </Security>
    </div>
  );
};

export const stixCoreObjectsExportsContentQuery = graphql`
  query StixCoreObjectsExportsContentRefetchQuery(
    $count: Int!
    $type: String!
  ) {
    ...StixCoreObjectsExportsContent_data @arguments(count: $count, type: $type)
  }
`;

export default createRefetchContainer(
  StixCoreObjectsExportsContentComponent,
  {
    data: graphql`
      fragment StixCoreObjectsExportsContent_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        type: { type: "String!" }
      ) {
        stixCoreObjectsExportFiles(first: $count, type: $type)
        @connection(key: "Pagination_stixCoreObjectsExportFiles") {
          edges {
            node {
              id
              ...FileLine_file
            }
          }
        }
        ...StixCoreObjectsExportCreation_data
      }
    `,
  },
  stixCoreObjectsExportsContentQuery,
);
