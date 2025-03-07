import React, { FunctionComponent, Suspense } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { DraftWorksQuery } from '@components/drafts/__generated__/DraftWorksQuery.graphql';
import { DraftWorksFragment$data } from '@components/drafts/__generated__/DraftWorksFragment.graphql';
import Chip from '@mui/material/Chip';
import { useTheme } from '@mui/styles';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { DataTableProps, DataTableVariant } from '../../../components/dataGrid/dataTableTypes';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';
import Loader, { LoaderVariant } from '../../../components/Loader';
import DataTableWithoutFragment from '../../../components/dataGrid/DataTableWithoutFragment';
import { hexToRGB } from '../../../utils/Colors';
import type { Theme } from '../../../components/Theme';

export const draftWorksFragment = graphql`
    fragment DraftWorksFragment on DraftWorkspace {
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

export const draftWorksQuery = graphql`
    query DraftWorksQuery($id: String!) {
      draftWorkspace(id: $id) {
        ...DraftWorksFragment
      }
    }
`;

const LOCAL_STORAGE_KEY = 'draft_works';

interface DraftWorksComponentProps {
  queryRef: PreloadedQuery<DraftWorksQuery>;
}
const DraftWorksComponent: FunctionComponent<
DraftWorksComponentProps
> = ({ queryRef }) => {
  const theme = useTheme<Theme>();
  const { draftWorkspace } = usePreloadedQuery<DraftWorksQuery>(draftWorksQuery, queryRef);
  const { id, works } = useFragment(draftWorksFragment, draftWorkspace) as DraftWorksFragment$data;

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
    <div data-testid="draft-works-page">
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

type DraftWorksProps = {
  draftId: string,
};

const DraftWorks = (props: DraftWorksProps) => {
  const { draftId } = props;
  const queryRef = useQueryLoading<DraftWorksQuery>(draftWorksQuery, { id: draftId });
  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <DraftWorksComponent queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default DraftWorks;
