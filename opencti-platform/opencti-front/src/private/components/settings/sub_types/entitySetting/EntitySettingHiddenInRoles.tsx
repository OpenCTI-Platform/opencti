import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import { SecurityOutlined } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { isEmptyField } from '../../../../../utils/utils';
import { useFormatter } from '../../../../../components/i18n';
import { EntitySettingHiddenInRolesQuery } from '../__generated__/EntitySettingHiddenInRolesQuery.graphql';

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

const EntitySettingHiddenInRoles = ({ targetType }: { targetType: string }) => {
  const { t } = useFormatter();
  const computeHiddenInRoles = () => {
    const data = useLazyLoadQuery<EntitySettingHiddenInRolesQuery>(entitySettingHiddenInRolesQuery, {});
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
      <Typography
        variant="h3"
        gutterBottom={true}
      >
        {t('Hidden in roles')}
      </Typography>
      <List>
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

export default EntitySettingHiddenInRoles;
