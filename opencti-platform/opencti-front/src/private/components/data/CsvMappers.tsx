import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import CsvMapperLines, {
  csvMapperLinesQuery,
} from '@components/data/csvMapper/CsvMapperLines';
import {
  CsvMapperLinesPaginationQuery,
  CsvMapperLinesPaginationQuery$variables,
} from '@components/data/csvMapper/__generated__/CsvMapperLinesPaginationQuery.graphql';
import CsvMapperCreationContainer from '@components/data/csvMapper/CsvMapperCreationContainer';
import { CsvMapperLine_csvMapper$data } from '@components/data/csvMapper/__generated__/CsvMapperLine_csvMapper.graphql';
import { CancelOutlined, CheckCircleOutlined } from '@mui/icons-material';
import ProcessingMenu from '@components/data/ProcessingMenu';
import ListLines from '../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import Loader, { LoaderVariant } from '../../../components/Loader';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

const LOCAL_STORAGE_KEY_CSV_MAPPERS = 'csvMappers';

const useStyles = makeStyles(() => ({
  container: {
    paddingRight: '200px',
  },
}));

const CsvMappers = () => {
  const classes = useStyles();

  const { viewStorage, paginationOptions, helpers } = usePaginationLocalStorage<CsvMapperLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_CSV_MAPPERS,
    {
      sortBy: 'name',
      orderAsc: false,
      searchTerm: '',
    },
  );
  const queryRef = useQueryLoading<CsvMapperLinesPaginationQuery>(
    csvMapperLinesQuery,
    paginationOptions,
  );
  const dataColumns = {
    name: {
      label: 'Name',
      width: '80%',
      isSortable: true,
      render: (data: CsvMapperLine_csvMapper$data) => data.name,
    },
    validity: {
      label: 'Validity',
      width: '20%',
      isSortable: false,
      render: (data: CsvMapperLine_csvMapper$data) => {
        return data.errors === null ? (
          <CheckCircleOutlined fontSize="small" color="success"/>
        ) : (
          <CancelOutlined fontSize="small" color="error"/>
        );
      },
    },
  };
  return (
    <div className={classes.container}>
      <ProcessingMenu/>
      <ListLines
        helpers={helpers}
        sortBy={viewStorage.sortBy}
        orderAsc={viewStorage.orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        displayImport={false}
        secondaryAction={true}
        keyword={viewStorage.searchTerm}
            >
        {queryRef && (
        <>
          <React.Suspense
            fallback={<Loader variant={LoaderVariant.inElement}/>}
                        >
            <CsvMapperLines
              queryRef={queryRef}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
                            />
          </React.Suspense>
        </>
        )}
      </ListLines>
      <CsvMapperCreationContainer paginationOptions={paginationOptions}/>
    </div>
  );
};

export default CsvMappers;
