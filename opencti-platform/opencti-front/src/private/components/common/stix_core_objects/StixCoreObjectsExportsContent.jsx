import React, { useEffect, useState } from 'react';
import { createRefetchContainer, graphql } from 'react-relay';
import List from '@mui/material/List';
import { interval } from 'rxjs';
import StixCoreObjectsExportCreation, { scopesConn } from './StixCoreObjectsExportCreation';
import { FIVE_SECONDS } from '../../../../utils/Time';
import FileLine from '../files/FileLine';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNGETEXPORT_KNASKEXPORT } from '../../../../utils/hooks/useGranted';
import { useFormatter } from '../../../../components/i18n';
import Button from '@common/button/Button';
import Tooltip from '@mui/material/Tooltip';
import * as R from 'ramda';
import { Stack } from '@mui/material';

const interval$ = interval(FIVE_SECONDS);

const StixCoreObjectsExportsContentComponent = ({
  relay,
  isOpen,
  data,
  exportContext,
  paginationOptions,
  exportType,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);

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

  const connectorsExport = data?.connectorsForExport ?? [];
  const exportScopes = R.uniq(
    R.flatten(R.map((c) => c.connector_scope, connectorsExport)),
  );
  const exportConnsPerFormat = scopesConn(connectorsExport);

  const isExportActive = (format) => R.filter((x) => x.data.active, exportConnsPerFormat[format]).length > 0;
  const isExportPossible = R.filter((x) => isExportActive(x), exportScopes).length > 0;

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
              ? t_i18n('Generate an export')
              : t_i18n('No export connector available to generate an export')
          }
          aria-label="generate-export"
        >
          <Button
            onClick={() => setOpen(true)}
            color="secondary"
            disabled={!isExportPossible}
          >
            {t_i18n('Generate an export')}
          </Button>
        </Tooltip>
      </Stack>
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
          exportType={exportType}
          open={open}
          setOpen={setOpen}
          onExportAsk={() => relay.refetch({ count: 25, exportContext })}
          exportScopes={exportScopes}
          isExportActive={isExportActive}
        />
      </Security>
    </>
  );
};

export const stixCoreObjectsExportsContentQuery = graphql`
  query StixCoreObjectsExportsContentRefetchQuery(
    $count: Int!
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
  stixCoreObjectsExportsContentQuery,
);
