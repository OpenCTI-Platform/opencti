import React from 'react';
import { MarkingDefinitionsLinesPaginationQuery } from '@components/settings/__generated__/MarkingDefinitionsLinesPaginationQuery.graphql';
import { MarkingDefinitionLineDummy } from './marking_definitions/MarkingDefinitionLine';
import { useFormatter } from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import MarkingDefinitionsLines, { markingDefinitionsLinesQuery } from './marking_definitions/MarkingDefinitionsLines';
import AccessesMenu from './AccessesMenu';
import MarkingDefinitionCreation from './marking_definitions/MarkingDefinitionCreation';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

const LOCAL_STORAGE_KEY = 'MarkingDefinitions';

const MarkingDefinitions = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Security: Marking Definitions | Settings'));

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<MarkingDefinitionsLinesPaginationQuery>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'definition',
      orderAsc: true,
      numberOfElements: {
        number: 0,
        symbol: '',
      },
    },
  );
  const queryPaginationOptions = { count: 25, ...paginationOptions };
  const queryRef = useQueryLoading<MarkingDefinitionsLinesPaginationQuery>(markingDefinitionsLinesQuery, queryPaginationOptions);

  const { sortBy, orderAsc, searchTerm, numberOfElements } = viewStorage;
  const dataColumns = {
    definition_type: {
      label: 'Type',
      width: '25%',
      isSortable: true,
    },
    definition: {
      label: 'Definition',
      width: '25%',
      isSortable: true,
    },
    x_opencti_color: {
      label: 'Color',
      width: '15%',
      isSortable: true,
    },
    x_opencti_order: {
      label: 'Order',
      width: '10%',
      isSortable: true,
    },
    created: {
      label: 'Original creation date',
      width: '15%',
      isSortable: true,
    },
  };

  return (
    <div
      style={{
        margin: 0,
        padding: '0 200px 0 0',
      }}
    >
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Security') }, { label: t_i18n('Marking definitions'), current: true }]} />
      <AccessesMenu />
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        displayImport={false}
        secondaryAction={false}
        keyword={searchTerm}
        numberOfElements={numberOfElements}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <MarkingDefinitionLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            }
          >
            <MarkingDefinitionsLines
              queryRef={queryRef}
              paginationOptions={queryPaginationOptions}
              dataColumns={dataColumns}
              setNumberOfElements={helpers.handleSetNumberOfElements}
            />
          </React.Suspense>
        )}
      </ListLines>
      <MarkingDefinitionCreation paginationOptions={queryPaginationOptions} />
    </div>
  );
};

export default MarkingDefinitions;
