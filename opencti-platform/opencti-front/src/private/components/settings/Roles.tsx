import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../utils/ListParameters';
import ListLines from '../../../components/list_lines/ListLines';
import RolesLines, { rolesLinesQuery } from './roles/RolesLines';
import AccessesMenu from './AccessesMenu';
import { OrderMode, PaginationOptions } from '../../../components/list_lines';
import RoleCreation from './roles/RoleCreation';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { RolesLinesPaginationQuery$data } from './roles/__generated__/RolesLinesPaginationQuery.graphql';
import { QueryRenderer } from '../../../relay/environment';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const LOCAL_STORAGE_KEY = 'roles';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const Role = () => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const location = useLocation();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Security: Roles | Settings'));
  const params = buildViewParamsFromUrlAndStorage(
    navigate,
    location,
    LOCAL_STORAGE_KEY,
  );
  const classes = useStyles();
  const [rolesState, setRolesState] = useState<{ orderAsc: boolean, searchTerm: string, view: string, sortBy: string }>({
    orderAsc: params.orderAsc !== false,
    searchTerm: params.searchTerm ?? '',
    view: params.view ?? 'lines',
    sortBy: params.sortBy ?? 'name',
  });

  function saveView() {
    saveViewParameters(
      navigate,
      location,
      LOCAL_STORAGE_KEY,
      rolesState,
    );
  }

  function handleSearch(value: string) {
    setRolesState({ ...rolesState, searchTerm: value });
  }

  function handleSort(field: string, orderAsc: boolean) {
    setRolesState({ ...rolesState, sortBy: field, orderAsc });
  }

  useEffect(() => {
    saveView();
  }, [rolesState]);

  function renderLines(paginationOptions: PaginationOptions) {
    const { sortBy, orderAsc } = rolesState;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '40%',
        isSortable: true,
      },
      groups: {
        label: 'Groups with this role',
        width: '20%',
        isSortable: false,
      },
      created_at: {
        label: 'Platform creation date',
        width: '20%',
        isSortable: true,
      },
      updated_at: {
        label: 'Modification date',
        width: '20%',
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
        keyword={rolesState.searchTerm}
        createButton={<RoleCreation paginationOptions={paginationOptions} />}
      >
        <QueryRenderer
          query={rolesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }: { props: RolesLinesPaginationQuery$data }) => (
            <RolesLines
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
    search: rolesState.searchTerm,
    orderBy: rolesState.sortBy ? rolesState.sortBy : null,
    orderMode: rolesState.orderAsc ? OrderMode.asc : OrderMode.desc,
  };
  return (
    <div className={classes.container} data-testid='roles-settings-page'>
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Security') }, { label: t_i18n('Roles'), current: true }]} />
      <AccessesMenu />
      {rolesState.view === 'lines' ? renderLines(paginationOptions) : ''}
    </div>
  );
};

export default Role;
