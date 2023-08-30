import React, { FunctionComponent } from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import NotesLines, { notesLinesQuery } from './notes/NotesLines';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNPARTICIPATE, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import ToolBar from '../data/ToolBar';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { NoteLineDummy } from './notes/NoteLine';
import { NoteLine_node$data } from './notes/__generated__/NoteLine_node.graphql';
import {
  NotesLinesPaginationQuery,
  NotesLinesPaginationQuery$variables,
} from './notes/__generated__/NotesLinesPaginationQuery.graphql';
import NoteCreation from './notes/NoteCreation';
import { filtersWithEntityType, initialFilterGroup } from '../../../utils/filters/filtersUtils';

const LOCAL_STORAGE_KEY = 'view-notes';

interface NotesProps {
  objectId: string;
  authorId: string;
  onChangeOpenExports: () => void;
}
const Notes: FunctionComponent<NotesProps> = ({ objectId, authorId, onChangeOpenExports }) => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const additionnalFilters = [];
  if (authorId) {
    additionnalFilters.push({
      key: 'createdBy',
      values: [authorId],
      operator: 'eq',
      mode: 'or',
    });
  }
  if (objectId) {
    additionnalFilters.push({
      key: 'objects',
      values: [objectId],
      operator: 'eq',
      mode: 'or',
    });
  }
  const {
    viewStorage,
    helpers: storageHelpers,
    paginationOptions } = usePaginationLocalStorage<NotesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      openExports: false,
      filters: initialFilterGroup,
    },
    additionnalFilters,
  );
  const {
    sortBy,
    orderAsc,
    searchTerm,
    filters,
    openExports,
    numberOfElements,
  } = viewStorage;

  const {
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    selectAll,
    handleToggleSelectAll,
  } = useEntityToggle<NoteLine_node$data>(LOCAL_STORAGE_KEY);
  const queryRef = useQueryLoading<NotesLinesPaginationQuery>(
    notesLinesQuery,
    paginationOptions,
  );
  const renderLines = () => {
    let exportContext = null;
    if (objectId) {
      exportContext = `of-entity-${objectId}`;
    } else if (authorId) {
      exportContext = `of-entity-${authorId}`;
    }
    const toolBarFilters = filtersWithEntityType(filters, 'Note');
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;
    const dataColumns = {
      attribute_abstract: {
        label: 'Abstract',
        width: '25%',
        isSortable: true,
      },
      note_types: {
        label: 'Type',
        width: '8%',
        isSortable: true,
      },
      createdBy: {
        label: 'Author',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      creator: {
        label: 'Creators',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      objectLabel: {
        label: 'Labels',
        width: '15%',
        isSortable: false,
      },
      created: {
        label: 'Date',
        width: '10%',
        isSortable: true,
      },
      x_opencti_workflow_id: {
        label: 'Status',
        width: '8%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: isRuntimeSort,
        width: '8%',
      },
    };
    return (
      <>
        <ListLines
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={storageHelpers.handleSort}
          handleSearch={storageHelpers.handleSearch}
          handleAddFilter={storageHelpers.handleAddFilter}
          handleRemoveFilter={storageHelpers.handleRemoveFilter}
          handleToggleExports={storageHelpers.handleToggleExports}
          handleSwitchGlobalMode={storageHelpers.handleSwitchGlobalMode}
          handleSwitchLocalMode={storageHelpers.handleSwitchLocalMode}
          openExports={openExports}
          handleToggleSelectAll={handleToggleSelectAll}
          selectAll={selectAll}
          noPadding={typeof onChangeOpenExports === 'function'}
          exportEntityType="Note"
          exportContext={exportContext}
          keyword={searchTerm}
          filters={filters}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
          iconExtension={true}
          availableFilterKeys={[
            'note_types',
            'x_opencti_workflow_id',
            'objectLabel',
            'objectMarking',
            'createdBy',
            'source_reliability',
            'confidence',
            'likelihood',
            'creator_id',
            'created',
          ]}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((idx) => (
                      <NoteLineDummy key={idx} dataColumns={dataColumns} />
                    ))}
                </>
              }
            >
              <NotesLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                onLabelClick={storageHelpers.handleAddFilter}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
              />
              <ToolBar
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                numberOfSelectedElements={numberOfSelectedElements}
                selectAll={selectAll}
                search={searchTerm}
                filters={toolBarFilters}
                handleClearSelectedElements={handleClearSelectedElements}
                type="Note"
              />
            </React.Suspense>
          )}
        </ListLines>
      </>
    );
  };
  return (
    <ExportContextProvider>
      {renderLines()}
      <Security needs={[KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNPARTICIPATE]}>
        <NoteCreation paginationOptions={paginationOptions} />
      </Security>
    </ExportContextProvider>
  );
};

export default Notes;
