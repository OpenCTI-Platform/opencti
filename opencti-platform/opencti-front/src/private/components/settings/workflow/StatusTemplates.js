import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { QueryRenderer } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import WorkflowsStatusesMenu from './WorkflowsStatusesMenu';
import StatusTemplateCreation from './StatusTemplateCreation';
import StatusTemplatesLines, { statusTemplatesLinesQuery } from './StatusTemplatesLines';
import useLocalStorage from '../../../../utils/hooks/useLocalStorage';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const LOCAL_STORAGE_KEY = 'view-status-templates';

const StatusTemplates = () => {
  const classes = useStyles();

  const [viewStorage, setViewStorage] = useLocalStorage(LOCAL_STORAGE_KEY, {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: false,
  });
  const { sortBy, orderAsc, searchTerm } = viewStorage;
  const queryVars = { search: searchTerm, orderMode: orderAsc ? 'asc' : 'desc', orderBy: sortBy };

  const handleSearch = (value) => setViewStorage({ searchTerm: value });

  const handleSort = (field, order) => setViewStorage((c) => ({
    ...c,
    sortBy: field,
    orderAsc: order,
  }));

  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'Name',
        width: '50%',
        isSortable: true,
      },
      color: {
        label: 'Color',
        width: '15%',
        isSortable: false,
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
        keyword={searchTerm}>
        <QueryRenderer
          query={statusTemplatesLinesQuery}
          variables={{ count: 25, ...queryVars }}
          render={({ props }) => (
            <StatusTemplatesLines
              data={props}
              paginationOptions={queryVars}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
    );
  };

  return (
    <div className={classes.container}>
      <WorkflowsStatusesMenu/>
      {renderLines()}
      <StatusTemplateCreation paginationOptions={queryVars}/>
    </div>
  );
};

export default StatusTemplates;
