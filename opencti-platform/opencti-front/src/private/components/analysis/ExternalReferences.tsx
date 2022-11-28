import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../relay/environment';
import { saveViewParameters } from '../../../utils/ListParameters';
import ListLines from '../../../components/list_lines/ListLines';
import ExternalReferencesLines, { externalReferencesLinesQuery } from './external_references/ExternalReferencesLines';
import ExternalReferenceCreation from './external_references/ExternalReferenceCreation';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';
import useLocalStorage, { localStorageToPaginationOptions } from '../../../utils/hooks/useLocalStorage';
import {
  ExternalReferencesLinesPaginationQuery$data,
  ExternalReferencesLinesPaginationQuery$variables,
} from './external_references/__generated__/ExternalReferencesLinesPaginationQuery.graphql';

export const externalReferencesSearchQuery = graphql`
  query ExternalReferencesSearchQuery(
    $search: String
    $filters: [ExternalReferencesFiltering]
  ) {
    externalReferences(search: $search, filters: $filters) {
      edges {
        node {
          id
          source_name
          external_id
          description
          url
        }
      }
    }
  }
`;

const LOCAL_STORAGE_KEY = 'view-external-references';

interface ExternalReferencesProps {
  history: History,
  location: Location,
}

const ExternalReferences: FunctionComponent<ExternalReferencesProps> = ({ history, location }) => {
  const [viewStorage, setViewStorage] = useLocalStorage(LOCAL_STORAGE_KEY, {
    searchTerm: '',
    sortBy: 'created',
    orderAsc: false,
    view: 'lines',
  });

  const { searchTerm, sortBy, orderAsc, view } = viewStorage;

  const paginationOptions = localStorageToPaginationOptions<ExternalReferencesLinesPaginationQuery$variables>({
    ...viewStorage,
    orderMode: orderAsc ? 'asc' : 'desc',
    search: searchTerm ?? '',
    count: 25,
  });

  const saveView = () => {
    saveViewParameters(
      history,
      location,
      'view-external_references',
      viewStorage,
    );
  };

  const handleSearch = (value: string) => {
    setViewStorage((c) => ({ ...c, searchTerm: value }));
    saveView();
  };

  const handleSort = (field: string, orderA: boolean) => {
    setViewStorage((c) => ({ ...c, sortBy: field, orderAsc: orderA }));
    saveView();
  };

  const renderLines = () => {
    const dataColumns = {
      source_name: {
        label: 'Source name',
        width: '15%',
        isSortable: true,
      },
      external_id: {
        label: 'External ID',
        width: '10%',
        isSortable: true,
      },
      url: {
        label: 'URL',
        width: '50%',
        isSortable: true,
      },
      created: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
    };
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={handleSort}
        handleSearch={handleSearch}
        displayImport={true}
        secondaryAction={true}
        keyword={searchTerm}
      >
        <QueryRenderer
          query={externalReferencesLinesQuery}
          variables={paginationOptions}
          render={({ props }: { props: ExternalReferencesLinesPaginationQuery$data }) => (
            <ExternalReferencesLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
    );
  };

  return (
    <div>
      {view === 'lines' ? renderLines() : ''}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <ExternalReferenceCreation paginationOptions={paginationOptions} openContextual={false}/>
      </Security>
    </div>
  );
};

export default ExternalReferences;
