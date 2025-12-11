import React, { FunctionComponent } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import DangerZoneChip from '@components/common/danger_zone/DangerZoneChip';
import { useFormatter } from '../../../../components/i18n';
import { roleEditionCapabilitiesLinesSearch } from './RoleEditionCapabilities';
import { RoleEditionCapabilitiesLinesSearchQuery } from './__generated__/RoleEditionCapabilitiesLinesSearchQuery.graphql';
import { Role_role$data } from './__generated__/Role_role.graphql';
import ItemIcon from '../../../../components/ItemIcon';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';

interface CapabilitiesListProps {
  queryRef: PreloadedQuery<RoleEditionCapabilitiesLinesSearchQuery>;
  role: Role_role$data;
  isCapabilitiesInDraft?: boolean;
}

const CapabilitiesList: FunctionComponent<CapabilitiesListProps> = ({
  queryRef,
  role,
  isCapabilitiesInDraft = false,
}) => {
  const { t_i18n } = useFormatter();

  const { capabilities, capabilitiesInDraft } = usePreloadedQuery<RoleEditionCapabilitiesLinesSearchQuery>(
    roleEditionCapabilitiesLinesSearch,
    queryRef,
  );

  const capabilitiesType = isCapabilitiesInDraft ? 'capabilitiesInDraft' : 'capabilities';
  const capabilitiesBaseList = isCapabilitiesInDraft ? capabilitiesInDraft : capabilities;

  const roleCapabilities = (role[capabilitiesType] ?? []).map((n) => ({
    name: n?.name,
  })) as { name: string }[];
  const { isSensitive } = useSensitiveModifications();

  return (
    <List>
      {(isSensitive && role.can_manage_sensitive_config) && (
        <ListItem
          key="sensitive"
          dense={true}
          divider={true}
          style={{ paddingLeft: 0 }}
        >
          <ListItemIcon style={{ minWidth: 32 }}>
            <ItemIcon type="Capability" />
          </ListItemIcon>
          <ListItemText
            primary={(
              <>
                {t_i18n('Allow modification of sensitive configuration')}
                <DangerZoneChip style={{ marginTop: 0 }} />
              </>
            )}
          />
        </ListItem>
      )}
      {capabilitiesBaseList?.edges?.map((edge, i) => {
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
          const draftCapaMatchingMainCapa = (role.capabilities ?? []).filter((r) => r?.name.includes(capability.name));
          const isDisabled = isCapabilitiesInDraft ? matchingCapabilities.length > 0 || draftCapaMatchingMainCapa.length > 0 : matchingCapabilities.length > 0;
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
                <ListItemText primary={t_i18n(capability.description)} />
              </ListItem>
            );
          }
        }
        return <div key={i} />;
      })}
    </List>
  );
};

export default CapabilitiesList;
