import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import ListLines from '../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { Filters } from '../../../components/list_lines';
import {
  CasesLinesPaginationQuery,
  CasesLinesPaginationQuery$variables,
} from './cases/__generated__/CasesLinesPaginationQuery.graphql';
import CasesLines, { casesLinesQuery } from './cases/CasesLines';
import { CaseLineDummy } from './cases/CaseLine';
import ManagementsMenu from './ManagementsMenu';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

interface CasesProps {
  inputValue?: string,
}

export const LOCAL_STORAGE_KEY_CASE = 'view-cases';

const Cases: FunctionComponent<CasesProps> = () => {
  const classes = useStyles();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<CasesLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY_CASE, {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: {} as Filters,
    numberOfElements: {
      number: 0,
      symbol: '',
    },
  });

  const renderLines = () => {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openExports,
      numberOfElements,
    } = viewStorage;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '20%',
        isSortable: true,
      },
      created: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      rating: {
        label: 'Rating',
        width: '10%',
        isSortable: true,
      },
      description: {
        label: 'Review',
        width: '15%',
        isSortable: false,
      },
      creator: {
        label: 'Creator',
        width: '10%',
        isSortable: true,
      },
      x_opencti_workflow_id: {
        label: 'Status',
        width: '10%',
        isSortable: true,
      },
    };

    const queryRef = useQueryLoading<CasesLinesPaginationQuery>(casesLinesQuery, paginationOptions);

    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleToggleExports={helpers.handleToggleExports}
        openExports={openExports}
        exportEntityType="Feedback"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'creator',
          'createdBy',
          'x_opencti_workflow_id',
        ]}
      >
        {queryRef && (
          <React.Suspense fallback={
            <>{[0, 1, 2].map((idx) => (<CaseLineDummy key={idx} dataColumns={dataColumns} />))}</>
          }>
            <CasesLines
              queryRef={queryRef}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              setNumberOfElements={helpers.handleSetNumberOfElements}
            />
          </React.Suspense>
        )}
      </ListLines>
    );
  };

  return (
    <div className={classes.container}>
      {renderLines()}
      <ManagementsMenu />
    </div>
  );
};

export default Cases;
