import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import { graphql, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import { SecurityOutlined } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import { isEmptyField } from '../../../../../utils/utils';
import { useFormatter } from '../../../../../components/i18n';
import { EntitySettingHiddenInRolesQuery } from './__generated__/EntitySettingHiddenInRolesQuery.graphql';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../../components/Loader';

const entitySettingHiddenInRolesQuery = graphql`
    query EntitySettingHiddenInRolesQuery($search: String) {
        roles(search: $search) {
            edges {
                node {
                    id
                    name
                    default_hidden_types
                }
            }
        }
    }
`;

interface EntitySettingHiddenProps {
  targetType: string
  queryRef: PreloadedQuery<EntitySettingHiddenInRolesQuery>
}

const EntitySettingHiddenInRolesComponent: FunctionComponent<EntitySettingHiddenProps> = ({ queryRef, targetType }) => {
  const { t } = useFormatter();
  const data = usePreloadedQuery<EntitySettingHiddenInRolesQuery>(entitySettingHiddenInRolesQuery, queryRef);
  const computeHiddenInRoles = () => {
    const rolesData = data.roles?.edges;
    const result = [];
    if (rolesData) {
      for (const role of rolesData) {
        if (role && role.node.default_hidden_types) {
          if (role.node.default_hidden_types.includes(targetType)) {
            result.push(role.node);
          }
        }
      }
    }
    return result;
  };
  const hiddenInRoles = computeHiddenInRoles();
  return (
    <div style={{ marginTop: 20 }}>
      <Typography variant="h3" gutterBottom={true}>
        {t('Hidden in roles')}
      </Typography>
      <List style={{ paddingTop: 0 }}>
        {isEmptyField(hiddenInRoles) ? <div>{'-'}</div> : (
          <>
            {hiddenInRoles.map((role) => (
              <ListItem
                key={role.id}
                dense={true}
                divider={true}
                button={true}
                component={Link}
                to={`/dashboard/settings/accesses/roles/${role.id}`}
              >
                <ListItemIcon>
                  <SecurityOutlined color="primary" />
                </ListItemIcon>
                <ListItemText primary={role.name} />
              </ListItem>
            ))}
          </>
        )}
      </List>
    </div>
  );
};

const EntitySettingHiddenInRoles: FunctionComponent<{ targetType: string }> = ({ targetType }) => {
  const queryRef = useQueryLoading<EntitySettingHiddenInRolesQuery>(entitySettingHiddenInRolesQuery, {});
  return <>
        {queryRef && (
            <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
                <EntitySettingHiddenInRolesComponent queryRef={queryRef} targetType={targetType} />
            </React.Suspense>
        )}
    </>;
};

export default EntitySettingHiddenInRoles;
