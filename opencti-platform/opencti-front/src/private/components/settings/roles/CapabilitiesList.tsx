import React, { FunctionComponent } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { roleEditionCapabilitiesLinesSearch } from './RoleEditionCapabilities';
import { RoleEditionCapabilitiesLinesSearchQuery } from './__generated__/RoleEditionCapabilitiesLinesSearchQuery.graphql';
import { Role_role$data } from './__generated__/Role_role.graphql';
import ItemIcon from '../../../../components/ItemIcon';

interface CapabilitiesListProps {
  queryRef: PreloadedQuery<RoleEditionCapabilitiesLinesSearchQuery>;
  role: Role_role$data;
}

const CapabilitiesList: FunctionComponent<CapabilitiesListProps> = ({
  queryRef,
  role,
}) => {
  const { t } = useFormatter();
  const roleCapabilities = (role.capabilities ?? []).map((n) => ({
    name: n?.name,
  })) as { name: string }[];
  const { capabilities } = usePreloadedQuery<RoleEditionCapabilitiesLinesSearchQuery>(
    roleEditionCapabilitiesLinesSearch,
    queryRef,
  );
  return (
    <List>
      {capabilities?.edges?.map((edge) => {
        const capability = edge?.node;
        if (capability) {
          const paddingLeft = (capability.name.split('_').length ?? -20) * 20 - 20;
          const roleCapability = roleCapabilities.find(
            (r) => r.name === capability.name,
          );
          const matchingCapabilities = roleCapabilities.filter(
            (r) => capability.name !== r.name
              && r.name.includes(capability.name)
              && capability.name !== 'BYPASS',
          );
          const isDisabled = matchingCapabilities.length > 0;
          const isChecked = isDisabled || roleCapability !== undefined;
          if (isChecked) {
            return (
              <ListItem
                key={capability.name}
                dense={true}
                divider={true}
                style={{ paddingLeft }}
              >
                <ListItemIcon style={{ minWidth: 32 }}>
                  <ItemIcon type="Capability" />
                </ListItemIcon>
                <ListItemText primary={t(capability.description)} />
              </ListItem>
            );
          }
        }
        return <div key="none" />;
      })}
    </List>
  );
};

export default CapabilitiesList;
