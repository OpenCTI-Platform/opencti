import React, { useEffect, useState } from 'react';
import { useHistory } from 'react-router-dom';
import { useLocation } from 'react-router-dom-v5-compat';
import { OrderMode, PaginationOptions } from 'src/components/list_lines';
import makeStyles from '@mui/styles/makeStyles';
import { TaxiiLinesPaginationQuery$data } from '@components/data/taxii/__generated__/TaxiiLinesPaginationQuery.graphql';
import { QueryRenderer } from '../../../relay/environment';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../utils/ListParameters';
import ListLines from '../../../components/list_lines/ListLines';
import TaxiiLines, { TaxiiLinesQuery } from './taxii/TaxiiLines';
import TaxiiCollectionCreation from './taxii/TaxiiCollectionCreation';
import SharingMenu from './SharingMenu';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const LOCAL_STORAGE_KEY = 'taxii';

const Taxii = () => {
  const classes = useStyles();
  const history = useHistory();
  const location = useLocation();
  const params = buildViewParamsFromUrlAndStorage(
    history,
    location,
    LOCAL_STORAGE_KEY,
  );
  const [taxiiState, setTaxiiState] = useState<{ orderAsc: boolean, searchTerm: string, view: string, sortBy: string }>({
    orderAsc: params.orderAsc !== false,
    searchTerm: params.searchTerm ?? '',
    view: params.view ?? 'lines',
    sortBy: '',
  });

  const saveView = () => {
    saveViewParameters(
      history,
      location,
      LOCAL_STORAGE_KEY,
      taxiiState,
    );
  };

  const handleSearch = (value: string) => {
    setTaxiiState({ ...taxiiState,
      searchTerm: value,
    });
  };

  const handleSort = (field: string, orderAsc: boolean) => {
    setTaxiiState({
      ...taxiiState,
      sortBy: field,
      orderAsc });
  };

  useEffect(() => {
    saveView();
  }, [taxiiState]);

  function renderLines(paginationOptions: PaginationOptions) {
    const { sortBy, orderAsc, searchTerm } = taxiiState;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '15%',
        isSortable: true,
      },
      description: {
        label: 'Description',
        width: '15%',
        isSortable: true,
      },
      id: {
        label: 'Collection',
        width: '25%',
        isSortable: true,
      },
      filters: {
        label: 'Filters',
        width: '45%',
      },
    };
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={handleSort}
        handleSearch={handleSearch}
        displayImport={false}
        secondaryAction={true}
        keyword={searchTerm}
      >
        <QueryRenderer
          query={TaxiiLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }: { props: TaxiiLinesPaginationQuery$data }) => (
            <TaxiiLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />)}
        />
      </ListLines>
    );
  }

  const paginationOptions: PaginationOptions = {
    search: taxiiState.searchTerm,
    orderBy: taxiiState.sortBy ? taxiiState.sortBy : null,
    orderMode: taxiiState.orderAsc ? OrderMode.asc : OrderMode.desc,
  };
  return (
    <div className={classes.container}>
      <SharingMenu/>
      {taxiiState.view === 'lines' ? renderLines(paginationOptions) : ''}
      <TaxiiCollectionCreation paginationOptions={paginationOptions}/>
    </div>
  );
};

export default Taxii;
