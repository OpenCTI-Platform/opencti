import React from 'react';
import {
  CitizenshipDocumentsLinesPaginationQuery,
  CitizenshipDocumentsLinesPaginationQuery$variables,
} from '@components/entities/citizenshipDocuments/__generated__/CitizenshipDocumentsLinesPaginationQuery.graphql';
import { CitizenshipDocumentLineDummy } from '@components/entities/citizenshipDocuments/CitizenshipDocumentLine';
import ListLines from '../../../components/list_lines/ListLines';
import CitizenshipDocumentsLines, { citizenshipDocumentsLinesQuery } from './citizenshipDocuments/CitizenshipDocumentsLines';
import CitizenshipDocumentCreation from './citizenshipDocuments/CitizenshipDocumentCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const LOCAL_STORAGE_KEY = 'citizenshipDocuments';

const CitizenshipDocuments = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Citizenship Documents | Entities'));
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<CitizenshipDocumentsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: emptyFilterGroup,
    },
  );
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
        width: '25%',
        isSortable: true,
      },
      x_opencti_citizenship_document_type: {
        label: 'Document Type',
        width: '25%',
        isSortable: false,
      },
      objectLabel: {
        label: 'Labels',
        width: '25%',
        isSortable: false,
      },
      created: {
        label: 'Original creation date',
        width: '12%',
        isSortable: true,
      },
      modified: {
        label: 'Modification date',
        width: '13%',
        isSortable: true,
      },
    };
    const queryRef = useQueryLoading<CitizenshipDocumentsLinesPaginationQuery>(
      citizenshipDocumentsLinesQuery,
      paginationOptions,
    );
    return (
      <ListLines
        helpers={helpers}
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
        handleSwitchLocalMode={helpers.handleSwitchLocalMode}
        handleToggleExports={helpers.handleToggleExports}
        openExports={openExports}
        exportContext={{ entity_type: 'CitizenshipDocument' }}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        createButton={(
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <CitizenshipDocumentCreation paginationOptions={paginationOptions} />
          </Security>
        )}
        iconExtension
      >
        {queryRef && (
          <React.Suspense
            fallback={(
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <CitizenshipDocumentLineDummy
                      key={idx}
                      dataColumns={dataColumns}
                    />
                  ))}
              </>
            )}
          >
            <CitizenshipDocumentsLines
              queryRef={queryRef}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              onLabelClick={helpers.handleAddFilter}
              setNumberOfElements={helpers.handleSetNumberOfElements}
            />
          </React.Suspense>
        )}
      </ListLines>
    );
  };

  return (
    <div data-testid="citizenshipDocument-page">
      <Breadcrumbs elements={[{ label: t_i18n('Entities') }, { label: t_i18n('Citizenship Documents'), current: true }]} />
      {renderLines()}
    </div>
  );
};

export default CitizenshipDocuments;
