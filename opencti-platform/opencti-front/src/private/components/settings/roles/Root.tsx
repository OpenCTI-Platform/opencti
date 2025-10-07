// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { FunctionComponent, useState } from 'react';
import { Route, Routes, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, useLazyLoadQuery, usePreloadedQuery } from 'react-relay';
import AccessesMenu from '@components/settings/AccessesMenu';
import Typography from '@mui/material/Typography';
import { Box, styled } from '@mui/material';
import MenuItem from '@mui/material/MenuItem';
import RoleDeletionDialog from '@components/settings/roles/RoleDeletionDialog';
import RoleEdition from '@components/settings/roles/RoleEdition';
import { useTheme } from '@mui/styles';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Role from './Role';
import { groupsSearchQuery } from '../Groups';
import { RootRoleQuery } from './__generated__/RootRoleQuery.graphql';
import { GroupsSearchQuery } from '../__generated__/GroupsSearchQuery.graphql';
import useGranted, { SETTINGS_SETACCESSES, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';
import PopoverMenu from '../../../../components/PopoverMenu';
import type { Theme } from '../../../../components/Theme';

const roleQuery = graphql`
  query RootRoleQuery($id: String!) {
    role(id: $id) {
      id
      standard_id
      name
      ...Role_role
      ...RoleEdition_role
    }
  }
`;

const roleEditionQuery = graphql`
  query RootRoleEditionQuery($id: String!) {
    role(id: $id) {
      ...RoleEdition_role
    }
  }
`;

interface RootRoleComponentProps {
  queryRef: PreloadedQuery<RootRoleQuery>,
}

const RootRoleComponent: FunctionComponent<RootRoleComponentProps> = ({ queryRef }) => {
  const data = usePreloadedQuery(roleQuery, queryRef);
  const { role } = data;
  const { t_i18n } = useFormatter();
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  const theme = useTheme<Theme>();
  const [openDelete, setOpenDelete] = useState(false);

  const handleOpenDelete = () => setOpenDelete(true);
  const handleCloseDelete = () => setOpenDelete(false);

  const { isAllowed, isSensitive } = useSensitiveModifications('roles', role.standard_id);
  const roleEditionData = useLazyLoadQuery<RoleEditionQuery>(
    roleEditionQuery,
    { id: role.id },
  );

  const groupsQueryRef = useQueryLoading<GroupsSearchQuery>(
    groupsSearchQuery,
    {
      count: 50,
      orderBy: 'name',
      orderMode: 'asc',
    },
  );

  const RoleHeader = styled('div')({
    display: 'flex',
    justifyContent: 'space-between',
    marginBottom: 24,
  });

  return (
    <Security needs={[SETTINGS_SETACCESSES]}>
      <>
        <AccessesMenu/>
        <Breadcrumbs
          isSensitive={isSensitive}
          elements={[
            { label: t_i18n('Settings') },
            { label: t_i18n('Security') },
            { label: t_i18n('Roles'), link: '/dashboard/settings/accesses/roles' },
            { label: role.name, current: true },
          ]}
        />
        <RoleHeader>
          <div>
            <Typography
              variant="h1"
              gutterBottom={true}
              style={{ float: 'left' }}
            >
              {role.name}
            </Typography>
            <div className="clearfix"/>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', paddingRight: 200 }}>
            <div style={{ display: 'flex' }}>
              <div style={{ marginRight: theme.spacing(0.5) }}>
                {canDelete && (
                <PopoverMenu>
                  {({ closeMenu }) => (
                    <Box>
                      <MenuItem
                        disabled={!isAllowed && isSensitive}
                        onClick={() => {
                          handleOpenDelete();
                          closeMenu();
                        }}
                      >
                        {t_i18n('Delete')}
                      </MenuItem>
                    </Box>
                  )}
                </PopoverMenu>
                )}
              </div>
              <RoleDeletionDialog
                roleId={role.id}
                isOpen={openDelete}
                handleClose={handleCloseDelete}
              />
              <RoleEdition
                roleEditionData={roleEditionData}
                disabled={!isAllowed && isSensitive}
              />
            </div>
          </div>
        </RoleHeader>
        <div className="clearfix"/>
        <>
          {groupsQueryRef ? (
            <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
              <Routes>
                <Route
                  path="/"
                  element={(
                    <Role roleData={role} groupsQueryRef={groupsQueryRef} />
                    )}
                />
              </Routes>
            </React.Suspense>
          ) : (
            <Loader variant={LoaderVariant.inElement} />
          )
            }
        </>
      </>
    </Security>
  );
};

const RootRole = () => {
  const { roleId } = useParams() as { roleId: string };
  const queryRef = useQueryLoading<RootRoleQuery>(roleQuery, { id: roleId });
  return (
    <div>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <RootRoleComponent queryRef={queryRef} roleId={roleId} />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </div>
  );
};

export default RootRole;
