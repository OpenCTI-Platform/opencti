import React, { FunctionComponent, Suspense } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Chip from '@mui/material/Chip';
import { useTheme } from '@mui/styles';
import { PirWorksQuery } from '@components/pir/__generated__/PirWorksQuery.graphql';
import { PirWorksFragment$data } from '@components/pir/__generated__/PirWorksFragment.graphql';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { DataTableProps, DataTableVariant } from '../../../components/dataGrid/dataTableTypes';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';
import Loader, { LoaderVariant } from '../../../components/Loader';
import DataTableWithoutFragment from '../../../components/dataGrid/DataTableWithoutFragment';
import { hexToRGB } from '../../../utils/Colors';
import type { Theme } from '../../../components/Theme';

export const pirWorksFragment = graphql`
  fragment PirWorksFragment on Pir {
    id
    works {
      id
      name
      connector {
        id
        name
      }
      status
      timestamp
      received_time
      completed_time
    }
  }
`;

export const pirWorksQuery = graphql`
  query PirWorksQuery($id: ID!) {
    pir(id: $id) {
      ...PirWorksFragment
    }
  }
`;

const LOCAL_STORAGE_KEY = 'pir_works';

interface PirWorksComponentProps {
  queryRef: PreloadedQuery<PirWorksQuery>;
}
const PirWorksComponent: FunctionComponent<
PirWorksComponentProps
> = ({ queryRef }) => {
  const theme = useTheme<Theme>();
  const { pir } = usePreloadedQuery<PirWorksQuery>(pirWorksQuery, queryRef);
  const { id, works } = useFragment(pirWorksFragment, pir) as PirWorksFragment$data;

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      percentWidth: 48,
      isSortable: false,
    },
    connector: {
      id: 'Connector',
      label: 'Connector',
      percentWidth: 20,
      isSortable: false,
      render: ({ connector }) => defaultRender(connector.name),
    },
    timestamp: {
      id: 'Timestamp',
      label: 'Start time',
      percentWidth: 20,
      isSortable: false,
      render: ({ timestamp }, h) => defaultRender(h.nsdt(timestamp)),
    },
    status: {
      id: 'Status',
      label: 'Status',
      percentWidth: 12,
      isSortable: false,
      render: ({ status }) => (
        <Chip
          variant="outlined"
          label={status}
          style={{
            fontSize: 12,
            lineHeight: '12px',
            height: 20,
            float: 'left',
            textTransform: 'uppercase',
            borderRadius: 4,
            width: 90,
            color: status === 'progress' || status === 'wait' ? theme.palette.warn.main : theme.palette.success.main,
            borderColor: status === 'progress' || status === 'wait' ? theme.palette.warn.main : theme.palette.success.main,
            backgroundColor: hexToRGB(status === 'progress' || status === 'wait' ? theme.palette.warn.main : theme.palette.success.main),
          }}
        />)
      ,
    },
  };

  return (
    <div data-testid="pir-works-page">
      {queryRef && (
        <DataTableWithoutFragment
          dataColumns={dataColumns}
          data={works}
          storageKey={`${LOCAL_STORAGE_KEY}-${id}`}
          isLocalStorageEnabled={false}
          globalCount={works ? works.length : 0}
          variant={DataTableVariant.inline}
          disableNavigation
        />
      )}
    </div>
  );
};

type PirWorksProps = {
  pirId: string,
};

const PirWorks = (props: PirWorksProps) => {
  const { pirId } = props;
  const queryRef = useQueryLoading<PirWorksQuery>(pirWorksQuery, { id: pirId });
  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <PirWorksComponent queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default PirWorks;
