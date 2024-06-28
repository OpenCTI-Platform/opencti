import React from 'react';
import { useFormatter } from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import LabelsLines, { labelsLinesQuery } from './labels/LabelsLines';
import LabelCreation from './labels/LabelCreation';
import LabelsVocabulariesMenu from './LabelsVocabulariesMenu';
import ToolBar from '../data/ToolBar';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

const LOCAL_STORAGE_KEY = 'Labels';

const Labels = () => {
  const { t_i18n } = useFormatter();

  const {
    viewStorage: { searchTerm, sortBy, orderAsc, numberOfElements },
    paginationOptions,
    helpers,
  } = usePaginationLocalStorage(LOCAL_STORAGE_KEY, {
    sortBy: 'value',
    orderAsc: true,
  });

  const {
    selectAll,
    selectedElements,
    deSelectedElements,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
  } = useEntityToggle(LOCAL_STORAGE_KEY);

  const contextFilters = {
    mode: 'and',
    filters: [
      {
        key: 'entity_type',
        values: ['Label'],
        operator: 'eq',
        mode: 'or',
      },
    ],
    filterGroups: [],
  };
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  };

  const queryRef = useQueryLoading(labelsLinesQuery, queryPaginationOptions);
  const renderLines = () => {
    let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
    if (selectAll) {
      numberOfSelectedElements = numberOfElements.original
        - Object.keys(deSelectedElements || {}).length;
    }
    const dataColumns = {
      value: {
        label: 'Value',
        width: '50%',
        isSortable: true,
      },
      color: {
        label: 'Color',
        width: '15%',
        isSortable: true,
      },
      created_at: {
        label: 'Platform creation date',
        width: '15%',
        isSortable: true,
      },
    };
    return (
      <>
        <ListLines
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={helpers.handleSort}
          handleSearch={helpers.handleSearch}
          handleToggleSelectAll={handleToggleSelectAll}
          selectAll={selectAll}
          numberOfElements={numberOfElements}
          iconExtension={true}
          displayImport={false}
          secondaryAction={true}
          keyword={searchTerm}
        >
          {queryRef && (
            <LabelsLines
              paginationOptions={queryPaginationOptions}
              dataColumns={dataColumns}
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              onToggleEntity={onToggleEntity}
              selectAll={selectAll}
              setNumberOfElements={helpers.handleSetNumberOfElements}
              queryRef={queryRef}
            />
          )}
        </ListLines>
        <ToolBar
          selectedElements={selectedElements}
          deSelectedElements={deSelectedElements}
          numberOfSelectedElements={numberOfSelectedElements}
          selectAll={selectAll}
          filters={contextFilters}
          search={searchTerm}
          handleClearSelectedElements={handleClearSelectedElements}
          type="Label"
          variant="medium"
        />
      </>
    );
  };

  return (
    <div
      style={{
        margin: 0,
        padding: '0 200px 50px 0',
      }}
    >
      <LabelsVocabulariesMenu />
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Taxonomies') }, { label: t_i18n('Labels'), current: true }]} />
      {renderLines()}
      <LabelCreation paginationOptions={queryPaginationOptions} />
    </div>
  );
};

export default Labels;
