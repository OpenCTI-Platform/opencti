import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../components/i18n';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../utils/ListParameters';
import ListLines from '../../../components/list_lines/ListLines';
import MarkingDefinitionsLines, { markingDefinitionsLinesQuery } from './marking_definitions/MarkingDefinitionsLines';
import AccessesMenu from './AccessesMenu';
import { OrderMode, PaginationOptions } from '../../../components/list_lines';
import MarkingDefinitionCreation from './marking_definitions/MarkingDefinitionCreation';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { MarkingDefinitionsLinesPaginationQuery$data } from './marking_definitions/__generated__/MarkingDefinitionsLinesPaginationQuery.graphql';
import { QueryRenderer } from '../../../relay/environment';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const LOCAL_STORAGE_KEY = 'MarkingDefinitions';

const MarkingDefinitions = () => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const location = useLocation();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Security: Marking Definitions | Settings'));
  const params = buildViewParamsFromUrlAndStorage(
    navigate,
    location,
    LOCAL_STORAGE_KEY,
  );

  const [markingDefinitionsState, setMarkingDefinitionsState] = useState<{ orderAsc: boolean, searchTerm: string, view: string, sortBy: string }>({
    orderAsc: params.orderAsc !== false,
    searchTerm: params.searchTerm ?? '',
    view: params.view ?? 'lines',
    sortBy: params.sortBy ?? 'definition',
  });

  function saveView() {
    saveViewParameters(
      navigate,
      location,
      LOCAL_STORAGE_KEY,
      markingDefinitionsState,
    );
  }

  function handleSearch(value: string) {
    setMarkingDefinitionsState({ ...markingDefinitionsState, searchTerm: value });
  }

  function handleSort(field: string, orderAsc: boolean) {
    setMarkingDefinitionsState({ ...markingDefinitionsState, sortBy: field, orderAsc });
  }

  useEffect(() => {
    saveView();
  }, [markingDefinitionsState]);

  function renderLines(paginationOptions: PaginationOptions) {
    const { sortBy, orderAsc, searchTerm } = markingDefinitionsState;
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
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={handleSort}
        handleSearch={handleSearch}
        displayImport={false}
        secondaryAction={false}
        keyword={searchTerm}
      >
        <QueryRenderer
          query={markingDefinitionsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }: { props: MarkingDefinitionsLinesPaginationQuery$data }) => (
            <MarkingDefinitionsLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
    );
  }

  const paginationOptions: PaginationOptions = {
    search: markingDefinitionsState.searchTerm,
    orderBy: markingDefinitionsState.sortBy ? markingDefinitionsState.sortBy : null,
    orderMode: markingDefinitionsState.orderAsc ? OrderMode.asc : OrderMode.desc,
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
      {markingDefinitionsState.view === 'lines' ? renderLines(paginationOptions) : ''}
      <MarkingDefinitionCreation paginationOptions={paginationOptions} />
    </div>
  );
};

export default MarkingDefinitions;
