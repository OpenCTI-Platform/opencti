import React, { useState, useEffect } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { graphql } from 'react-relay';
import { useLocation, useNavigate } from 'react-router-dom';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../utils/ListParameters';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import GroupsLines, { groupsLinesQuery } from './groups/GroupsLines';
import GroupCreation from './groups/GroupCreation';
import { OrderMode, PaginationOptions } from '../../../components/list_lines';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { GroupsLinesPaginationQuery$data } from './groups/__generated__/GroupsLinesPaginationQuery.graphql';
import AccessesMenu from './AccessesMenu';
import { QueryRenderer } from '../../../relay/environment';

const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

export const groupsSearchQuery = graphql`
  query GroupsSearchQuery($search: String) {
    groups(search: $search) {
      edges {
        node {
          id
          name
          description
          created_at
          updated_at
          roles {
            edges {
              node {
                id
                name
              }
            }
          }
          group_confidence_level {
            max_confidence
          }
        }
      }
    }
  }
`;

const LOCAL_STORAGE_KEY = 'groups';

const Groups = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const location = useLocation();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Security: Groups | Settings'));
  const params = buildViewParamsFromUrlAndStorage(
    navigate,
    location,
    LOCAL_STORAGE_KEY,
  );

  const [groupState, setGroupState] = useState<{ orderAsc: boolean, searchTerm: string, view: string, sortBy: string }>({
    sortBy: params.sortBy ?? 'name',
    orderAsc: params.orderAsc !== false,
    searchTerm: params.searchTerm ?? '',
    view: params.view ?? 'lines',
  });

  function saveView() {
    saveViewParameters(
      navigate,
      location,
      LOCAL_STORAGE_KEY,
      groupState,
    );
  }

  function handleSearch(value: string) {
    setGroupState({ ...groupState, searchTerm: value });
  }

  function handleSort(field: string, orderAsc: boolean) {
    setGroupState({ ...groupState, sortBy: field, orderAsc });
  }

  useEffect(() => {
    saveView();
  }, [groupState]);

  function renderLines(paginationOptions: PaginationOptions) {
    const { sortBy, orderAsc, searchTerm } = groupState;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '20%',
        isSortable: true,
      },
      default_assignation: {
        label: 'Default membership',
        width: '12%',
        isSortable: true,
      },
      auto_new_marking: {
        label: 'Auto new markings',
        width: '12%',
        isSortable: true,
      },
      no_creators: {
        label: 'No creators',
        width: '12%',
        isSortable: true,
      },
      group_confidence_level: {
        label: 'Max Confidence',
        width: '12%',
        isSortable: true,
      },
      created_at: {
        label: 'Platform creation date',
        width: '15%',
        isSortable: true,
      },
      updated_at: {
        label: 'Modification date',
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
        createButton={<GroupCreation paginationOptions={paginationOptions} />}
      >
        <QueryRenderer
          query={groupsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }: { props: GroupsLinesPaginationQuery$data }) => (
            <GroupsLines
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
    search: groupState.searchTerm,
    orderBy: groupState.sortBy ? groupState.sortBy : null,
    orderMode: groupState.orderAsc ? OrderMode.asc : OrderMode.desc,
  };

  return (
    <div className={classes.container} data-testid="groups-settings-page">
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Security') }, { label: t_i18n('Groups'), current: true }]} />
      <AccessesMenu />
      {groupState.view === 'lines' ? renderLines(paginationOptions) : ''}
    </div>
  );
};

export default Groups;
