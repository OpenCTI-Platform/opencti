import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import ListLines from '../../../components/list_lines/ListLines';
import SettingsOrganizationsLines, { settingsOrganizationsLinesQuery } from './organizations/SettingsOrganizationsLines';
import Loader, { LoaderVariant } from '../../../components/Loader';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { SettingsOrganizationsLinesPaginationQuery, SettingsOrganizationsLinesPaginationQuery$variables } from './organizations/__generated__/SettingsOrganizationsLinesPaginationQuery.graphql';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import AccessesMenu from './AccessesMenu';
import { useFormatter } from '../../../components/i18n';
import { SettingsOrganizationLine_node$data as Organization } from './organizations/__generated__/SettingsOrganizationLine_node.graphql';
import useAuth from '../../../utils/hooks/useAuth';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const SettingsOrganizations = () => {
  const classes = useStyles();
  const { me } = useAuth();
  const LOCAL_STORAGE_KEY = 'view-settings-organizations';
  const { viewStorage, helpers, paginationOptions: paginationOptionsFromStorage } = usePaginationLocalStorage<SettingsOrganizationsLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: false,
  });

  const userIsOrganizationAdmin = (me.administrated_organizations ?? []).length > 0;
  const paginationOptions = {
    ...paginationOptionsFromStorage,
    filters: userIsOrganizationAdmin ? [{ key: ['authorized_authorities'], values: [me.id] }] : undefined,
  };

  const queryRef = useQueryLoading<SettingsOrganizationsLinesPaginationQuery>(settingsOrganizationsLinesQuery, paginationOptions);
  const { fd, t } = useFormatter();

  const dataColumns = {
    name: {
      label: 'Name',
      width: '30%',
      isSortable: true,
      render: (node: Organization) => node.name,
    },
    x_opencti_organization_type: {
      label: 'Type',
      width: '20%',
      isSortable: true,
      render: (node: Organization) => (node.x_opencti_organization_type ? t(`organization_${node.x_opencti_organization_type}`)
        : ''),
    },
    created: {
      label: 'Creation date',
      width: '15%',
      isSortable: true,
      render: (node: Organization) => fd(node.created),
    },
    modified: {
      label: 'Modification date',
      width: '15%',
      isSortable: true,
      render: (node: Organization) => fd(node.modified),
    },
  };
  return (
    <div className={classes.container}>
      <AccessesMenu />
      <ListLines
        sortBy={viewStorage.sortBy}
        orderAsc={viewStorage.orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        keyword={paginationOptions.search}
        paginationOptions={paginationOptions}
      >
        {queryRef && (
          <>
            <React.Suspense
              fallback={<Loader variant={LoaderVariant.inElement} />}
            >
              <SettingsOrganizationsLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
              />
            </React.Suspense>
          </>
        )}
      </ListLines>
    </div>
  );
};
export default SettingsOrganizations;
