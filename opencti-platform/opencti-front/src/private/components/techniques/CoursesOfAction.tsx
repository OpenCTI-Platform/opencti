import React from 'react';
import {
  CoursesOfActionLinesPaginationQuery,
  CoursesOfActionLinesPaginationQuery$variables,
} from '@components/techniques/courses_of_action/__generated__/CoursesOfActionLinesPaginationQuery.graphql';
import { CourseOfActionLineDummy } from '@components/techniques/courses_of_action/CourseOfActionLine';
import CourseOfActionCreation from '@components/techniques/courses_of_action/CourseOfActionCreation';
import ListLines from '../../../components/list_lines/ListLines';
import CoursesOfActionLines, { coursesOfActionLinesQuery } from './courses_of_action/CoursesOfActionLines';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { initialFilterGroup } from '../../../utils/filters/filtersUtils';

const LOCAL_STORAGE_KEY = 'view-coursesOfAction';

const CoursesOfAction = () => {
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<CoursesOfActionLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: initialFilterGroup,
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
        width: '35%',
        isSortable: true,
      },
      objectLabel: {
        label: 'Labels',
        width: '25%',
        isSortable: false,
      },
      created: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      modified: {
        label: 'Modification date',
        width: '15%',
        isSortable: true,
      },
    };
    const queryRef = useQueryLoading<CoursesOfActionLinesPaginationQuery>(
      coursesOfActionLinesQuery,
      paginationOptions,
    );
    return (
      <ListLines
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
        exportEntityType="Course-Of-Action"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'x_opencti_workflow_id',
          'objectLabel',
          'objectMarking',
          'createdBy',
          'source_reliability',
          'creator_id',
          'created',
          'revoked',
        ]}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((idx) => (
                    <CourseOfActionLineDummy
                      key={idx}
                      dataColumns={dataColumns}
                    />
                  ))}
              </>
            }
          >
            <CoursesOfActionLines
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
    <div>
      {renderLines()}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <CourseOfActionCreation paginationOptions={paginationOptions} />
      </Security>
    </div>
  );
};

export default CoursesOfAction;
