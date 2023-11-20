import React, { FunctionComponent } from 'react';
import {
  WorkspacesFilter,
  WorkspacesLinesPaginationQuery,
  WorkspacesLinesPaginationQuery$variables,
} from '@components/workspaces/__generated__/WorkspacesLinesPaginationQuery.graphql';
import { WorkspaceLineDummy } from '@components/workspaces/WorkspaceLine';
import ListLines from '../../../components/list_lines/ListLines';
import WorkspacesLines, { workspacesLinesQuery } from './WorkspacesLines';
import WorkspaceCreation from './WorkspaceCreation';
import Security from '../../../utils/Security';
import { EXPLORE_EXUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

interface WorkspacesProps {
  type: string;
}

const Workspaces: FunctionComponent<WorkspacesProps> = ({
  type,
}) => {
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<WorkspacesLinesPaginationQuery$variables>(
    `view-${type}-list`,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: false,
      openExports: false,
      redirectionMode: 'overview',
      view: 'lines',
    },
  );

  const {
    numberOfElements,
    searchTerm,
    sortBy,
    orderAsc,
  } = viewStorage;

  const workspacePaginationOptions = { ...paginationOptions, filters: [{ key: ['type' as WorkspacesFilter], values: [type] }] };

  const queryRef = useQueryLoading<WorkspacesLinesPaginationQuery>(
    workspacesLinesQuery,
    workspacePaginationOptions,
  );

  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'Name',
        width: '35%',
        isSortable: true,
      },
      tags: {
        label: 'Tags',
        width: '25%',
        isSortable: false,
      },
      creator: {
        label: 'Creator',
        width: '10%',
        isSortable: true,
      },
      created_at: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      updated_at: {
        label: 'Modification date',
        width: '15%',
        isSortable: true,
      },
    };
    return (
      <ListLines
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={storageHelpers.handleSort}
          handleSearch={storageHelpers.handleSearch}
          keyword={searchTerm}
          secondaryAction={true}
          paginationOptions={workspacePaginationOptions}
          numberOfElements={numberOfElements}
      >
        {queryRef && (
          <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((idx) => (
                          <WorkspaceLineDummy key={idx} dataColumns={dataColumns}/>
                    ))}
                </>
              }
          >
            <WorkspacesLines
                queryRef={queryRef}
                paginationOptions={workspacePaginationOptions}
                dataColumns={dataColumns}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
            />
          </React.Suspense>
        )}
        </ListLines>
    );
  };

  return (
      <>
        {renderLines()}
        <Security needs={[EXPLORE_EXUPDATE]}>
          <WorkspaceCreation
              paginationOptions={workspacePaginationOptions}
              type={type}
          />
        </Security>
      </>
  );
};

export default Workspaces;
