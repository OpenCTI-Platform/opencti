import React from 'react';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import {
  DataSourcesLinesPaginationQuery$variables,
} from '../../techniques/data_sources/__generated__/DataSourcesLinesPaginationQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import SubTypesLines, { subTypesLinesQuery } from './SubTypesLines';
import ListLines from '../../../../components/list_lines/ListLines';
import { SubTypeLineDummy } from './SubTypesLine';
import { SubTypesLinesQuery } from './__generated__/SubTypesLinesQuery.graphql';

const LOCAL_STORAGE_KEY_SUB_TYPES = 'view-sub-types';

const SubTypes = () => {
  const {
    viewStorage,
    helpers,
    paginationOptions,
  } = usePaginationLocalStorage<DataSourcesLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY_SUB_TYPES, {
    searchTerm: '',
  });

  const dataColumns = {
    entity_type: {
      label: 'Entity types',
      width: '100%',
      isSortable: false,
    },
  };

  const { searchTerm } = viewStorage;
  const queryRef = useQueryLoading<SubTypesLinesQuery>(subTypesLinesQuery, paginationOptions);

  return (
    <ListLines
      handleSearch={helpers.handleSearch}
      keyword={searchTerm}
      dataColumns={dataColumns}
    >
      {queryRef && (
        <React.Suspense fallback={
          <>{Array.from(Array(20).keys())
            .map((idx) => <SubTypeLineDummy key={idx} dataColumns={dataColumns} />)}</>
        }>
          <SubTypesLines queryRef={queryRef} keyword={searchTerm} dataColumns={dataColumns} />
        </React.Suspense>
      )}
    </ListLines>
  );
};

export default SubTypes;
