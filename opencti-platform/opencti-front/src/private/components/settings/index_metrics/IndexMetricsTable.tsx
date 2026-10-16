import React from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { IndexMetricsTableQuery } from './__generated__/IndexMetricsTableQuery.graphql';
import { Box, Typography } from '@mui/material';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import DataTableWithoutFragment from 'src/components/dataGrid/DataTableWithoutFragment';
import ItemBoolean from '../../../../components/ItemBoolean';
import { ErrorOutlined, WarningOutlined } from '@mui/icons-material';

export const LOCAL_STORAGE_KEY_INDEX_METRICS = 'index-metrics';

const indexMetricsTableQuery = graphql`
  query IndexMetricsTableQuery {
    dataIndexMetrics {
      indexes{
        name,
        uuid,
        health,
        status,
        primaries {
            docs {
                count
                total_size_in_bytes
            }
        }
      }
    }
  }
`;
const IndexMetricsTableComponent = () => {
  const { t_i18n, b } = useFormatter();
  const data = useLazyLoadQuery<IndexMetricsTableQuery>(indexMetricsTableQuery, {});
  const indexes = data.dataIndexMetrics?.indexes ? data.dataIndexMetrics.indexes.filter((i) => !i?.name?.includes('.internal')) : [];

  const healthIcon = (health: string | undefined) => {
    if (health === 'red') {
      return <ErrorOutlined color="error" />;
    }
    if (health === 'yellow') {
      return <WarningOutlined color="warning" />;
    }
  };

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      label: t_i18n('Index name'),
      isSortable: false,
      percentWidth: 50,
    },
    health: {
      label: t_i18n('Index health'),
      isSortable: false,
      percentWidth: 15,
      render: ({ health }: { health?: string }) => (
        <Box sx={{ display: 'flex', gap: 2 }}>
          {
            healthIcon(health)
          }
          <Typography>{health}</Typography>
        </Box>
      ),
    },
    status: {
      label: t_i18n('Index status'),
      isSortable: false,
      percentWidth: 10,
      render: ({ status }: { status?: string }) => (
        <ItemBoolean
          status={status === 'open'}
          label={status === 'open' ? t_i18n('Open') : t_i18n('Closed')}
        />
      ),
    },
    documents: {
      label: t_i18n('Document count'),
      percentWidth: 15,
      render: ({ documents }: { documents?: number }) => (
        <Typography>{documents}</Typography>
      ),
    },
    size: {
      label: t_i18n('Index size'),
      isSortable: false,
      percentWidth: 10,
      render: ({ size }: { size?: string }) => (
        <Typography>{size}</Typography>
      ),
    },
  };

  return (
    <DataTableWithoutFragment
      dataColumns={dataColumns}
      data={indexes.map((i) => {
        return {
          name: i?.name,
          health: i?.health,
          status: i?.status,
          documents: i?.primaries?.docs?.count,
          size: b(i?.primaries?.docs?.total_size_in_bytes),
        };
      })}
      storageKey={LOCAL_STORAGE_KEY_INDEX_METRICS}
      globalCount={indexes.length}
      disableToolBar
      disableNavigation
      disableLineSelection
      isLocalStorageEnabled={false}
    />
  );
};

const IndexMetricsTable = () => {
  return (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <IndexMetricsTableComponent />
    </React.Suspense>
  );
};

export default IndexMetricsTable;
