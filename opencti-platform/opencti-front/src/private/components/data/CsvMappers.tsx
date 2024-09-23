import React, { Suspense } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import CsvMapperLines from '@components/data/csvMapper/CsvMapperLines';
import CsvMapperCreationContainer from '@components/data/csvMapper/CsvMapperCreationContainer';
import { CsvMapperLine_csvMapper$data } from '@components/data/csvMapper/__generated__/CsvMapperLine_csvMapper.graphql';
import { CancelOutlined, CheckCircleOutlined } from '@mui/icons-material';
import ProcessingMenu from '@components/data/ProcessingMenu';
import CsvMappersProvider, { mappersQuery, schemaAttributesQuery } from '@components/data/csvMapper/csvMappers.data';
import { csvMappers_MappersQuery, csvMappers_MappersQuery$variables } from '@components/data/csvMapper/__generated__/csvMappers_MappersQuery.graphql';
import { csvMappers_SchemaAttributesQuery } from '@components/data/csvMapper/__generated__/csvMappers_SchemaAttributesQuery.graphql';
import ListLines from '../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import Loader, { LoaderVariant } from '../../../components/Loader';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';

const LOCAL_STORAGE_KEY_CSV_MAPPERS = 'csvMappers';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    paddingRight: '200px',
  },
}));

const CsvMappers = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { viewStorage, paginationOptions, helpers } = usePaginationLocalStorage<csvMappers_MappersQuery$variables>(
    LOCAL_STORAGE_KEY_CSV_MAPPERS,
    {
      sortBy: 'name',
      orderAsc: false,
      view: 'lines',
      searchTerm: '',
    },
  );

  const queryRefSchemaAttributes = useQueryLoading<csvMappers_SchemaAttributesQuery>(
    schemaAttributesQuery,
  );
  const queryRefMappers = useQueryLoading<csvMappers_MappersQuery>(
    mappersQuery,
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

  return queryRefMappers && queryRefSchemaAttributes
    && (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement}/>}>
        <CsvMappersProvider
          mappersQueryRef={queryRefMappers}
          schemaAttributesQueryRef={queryRefSchemaAttributes}
        >
          <div className={classes.container}>
            <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Processing') }, { label: t_i18n('CSV mappers'), current: true }]} />
            <ProcessingMenu />
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
              paginationOptions={paginationOptions}
              numberOfElements={viewStorage.numberOfElements}
            >
              <React.Suspense
                fallback={<Loader variant={LoaderVariant.inElement}/>}
              >
                <CsvMapperLines
                  paginationOptions={paginationOptions}
                  dataColumns={dataColumns}
                />
              </React.Suspense>
            </ListLines>
            <CsvMapperCreationContainer paginationOptions={paginationOptions}/>
          </div>
        </CsvMappersProvider>
      </Suspense>
    );
};

export default CsvMappers;
