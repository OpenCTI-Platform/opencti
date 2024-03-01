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
  exportContext,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      if (isOpen) {
        relay.refetch({
          exportContext,
          count: 25,
        });
      }
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  });
  const stixCoreObjectsExportFiles = data?.stixCoreObjectsExportFiles?.edges ?? [];
  return (
    <>
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
              {t_i18n('No file for the moment')}
            </span>
          </div>
        )}
      </List>
      <Security needs={[KNOWLEDGE_KNGETEXPORT_KNASKEXPORT]}>
        <StixCoreObjectsExportCreation
          data={data}
          exportContext={exportContext}
          paginationOptions={paginationOptions}
          onExportAsk={() => relay.refetch({ count: 25, exportContext })}
        />
      </Security>
    </>
  );
};

export const stixCoreObjectsExportsContentQuery = graphql`
  query StixCoreObjectsExportsContentRefetchQuery(
    $count: Int
    $exportContext: ExportContext!
  ) {
    ...StixCoreObjectsExportsContent_data @arguments(count: $count, exportContext: $exportContext)
  }
`;

export default createRefetchContainer(
  StixCoreObjectsExportsContentComponent,
  {
    data: graphql`
      fragment StixCoreObjectsExportsContent_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        exportContext: { type: "ExportContext!" }
      ) {
        stixCoreObjectsExportFiles(first: $count, exportContext: $exportContext)
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
