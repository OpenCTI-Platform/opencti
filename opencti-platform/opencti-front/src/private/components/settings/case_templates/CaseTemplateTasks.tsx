import makeStyles from '@mui/styles/makeStyles';
import React from 'react';
import { useParams } from 'react-router-dom';
import ListLines from '../../../../components/list_lines/ListLines';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { BackendFilters } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import LabelsVocabulariesMenu from '../LabelsVocabulariesMenu';
import { CaseTemplateTasksLine_node$data } from './__generated__/CaseTemplateTasksLine_node.graphql';
import { CaseTemplateTasksLines_DataQuery$variables } from './__generated__/CaseTemplateTasksLines_DataQuery.graphql';
import { CaseTemplateTasksLinesPaginationQuery } from './__generated__/CaseTemplateTasksLinesPaginationQuery.graphql';
import CaseTemplateTasksLines, { tasksLinesQuery } from './CaseTemplateTasksLines';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
  label: {
    fontSize: 12,
    height: 20,
    float: 'left',
    marginRight: 7,
  },
}));

const CaseTemplateTasks = () => {
  const classes = useStyles();
  const { caseTemplateId } = useParams() as { caseTemplateId: string };
  const taskFilters : BackendFilters = [{ key: 'objectContains', values: [caseTemplateId] }, { key: 'useAsTemplate', values: ['true'] }];
  const { viewStorage, paginationOptions, helpers } = usePaginationLocalStorage<CaseTemplateTasksLines_DataQuery$variables>(
    'view-case-template-tasks',
    {
      sortBy: 'name',
      orderAsc: true,
      searchTerm: '',
    },
    taskFilters,
  );
  const queryRef = useQueryLoading<CaseTemplateTasksLinesPaginationQuery>(
    tasksLinesQuery,
    paginationOptions,
  );
  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'Name',
        width: '25%',
        isSortable: true,
        render: (node: CaseTemplateTasksLine_node$data) => (node.name),
      },
      description: {
        label: 'Description',
        width: '65%',
        isSortable: true,
        render: (node: CaseTemplateTasksLine_node$data) => (node.description),
      },
    };
    return (
      <ListLines
        sortBy={viewStorage.sortBy}
        orderAsc={viewStorage.orderAsc}
        dataColumns={dataColumns}
        keyword={paginationOptions.search}
        filters={viewStorage.filters}
        handleSearch={helpers.handleSearch}
        numberOfElements={viewStorage.numberOfElements}
        handleSort={helpers.handleSort}
        secondaryAction
      >
        {queryRef && (
          <>
            <React.Suspense
              fallback={<Loader variant={LoaderVariant.inElement} />}
            >
              <CaseTemplateTasksLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                setNumberOfElements={helpers.handleSetNumberOfElements}
              />
            </React.Suspense>
          </>
        )}
      </ListLines>
    );
  };
  return (
    <div className={classes.container}>
      <LabelsVocabulariesMenu />
      {renderLines()}
    </div>
  );
};

export default CaseTemplateTasks;
