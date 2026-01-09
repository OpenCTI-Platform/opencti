import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql, usePreloadedQuery } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Checkbox from '@mui/material/Checkbox';
import List from '@mui/material/List';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import ListItemIcon from '@mui/material/ListItemIcon';
import LocalPoliceOutlined from '@mui/icons-material/LocalPoliceOutlined';
import { useTheme } from '@mui/styles';
import DangerZoneChip from '@components/common/danger_zone/DangerZoneChip';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { RoleEditionCapabilitiesLinesSearchQuery } from './__generated__/RoleEditionCapabilitiesLinesSearchQuery.graphql';
import { RoleEditionCapabilities_role$data } from './__generated__/RoleEditionCapabilities_role.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { SETTINGS } from '../../../../utils/hooks/useGranted';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';
import type { Theme } from '../../../../components/Theme';
import { Stack } from '@mui/material';

const roleEditionAddCapability = graphql`
  mutation RoleEditionCapabilitiesAddCapabilityMutation(
    $id: ID!
    $input: InternalRelationshipAddInput!
  ) {
    roleEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...RoleEditionCapabilities_role
        }
      }
    }
  }
`;

const roleEditionRemoveCapability = graphql`
  mutation RoleEditionCapabilitiesDelCapabilityMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    roleEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...RoleEditionCapabilities_role
      }
    }
  }
`;

const roleEditionPatchAllowSensitiveConf = graphql`
  mutation RoleEditionCapabilitiesPatchAllowSensitiveChangesMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    roleEdit(id: $id) {
      fieldPatch(input: $input) {
        can_manage_sensitive_config
      }
    }
  }
`;

export const roleEditionCapabilitiesLinesSearch = graphql`
  query RoleEditionCapabilitiesLinesSearchQuery {
    capabilities(first: 500) {
      edges {
        node {
          id
          name
          description
        }
      }
    }
    capabilitiesInDraft(first: 500) {
      edges {
        node {
          id
          name
          description
        }
      }
    }
  }
`;

interface RoleEditionCapabilitiesComponentProps {
  role: RoleEditionCapabilities_role$data;
  queryRef: PreloadedQuery<RoleEditionCapabilitiesLinesSearchQuery>;
  isCapabilitiesInDraft?: boolean;
}

const RoleEditionCapabilitiesComponent: FunctionComponent<RoleEditionCapabilitiesComponentProps> = ({ role, queryRef, isCapabilitiesInDraft = false }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const { capabilities, capabilitiesInDraft } = usePreloadedQuery<RoleEditionCapabilitiesLinesSearchQuery>(
    roleEditionCapabilitiesLinesSearch,
    queryRef,
  );

  const relationshipType = isCapabilitiesInDraft ? 'has-capability-in-draft' : 'has-capability';
  const capabilitiesType = isCapabilitiesInDraft ? 'capabilitiesInDraft' : 'capabilities';
  const capabilitiesBaseList = isCapabilitiesInDraft ? capabilitiesInDraft : capabilities;

  const roleCapabilities = (role[capabilitiesType] ?? []).map((n) => ({
    name: n?.name,
  })) as { name: string }[];
  const [commitAddCapability] = useApiMutation(roleEditionAddCapability);
  const [commitRemoveCapability] = useApiMutation(roleEditionRemoveCapability);
  const [commitPatchAllowSensitiveConf] = useApiMutation(roleEditionPatchAllowSensitiveConf);
  const handleToggle = (
    capabilityId: string,
    event: React.ChangeEvent<HTMLInputElement>,
  ) => {
    const roleId = role.id;
    if (event.target.checked) {
      commitAddCapability({
        variables: {
          id: roleId,
          input: {
            toId: capabilityId,
            relationship_type: relationshipType,
          },
        },
      });
    } else {
      commitRemoveCapability({
        variables: {
          id: roleId,
          toId: capabilityId,
          relationship_type: relationshipType,
        },
      });
    }
  };

  const handleSensitiveToggle = (
    event: React.ChangeEvent<HTMLInputElement>,
  ) => {
    const roleId = role.id;
    commitPatchAllowSensitiveConf({
      variables: {
        id: roleId,
        input: {
          key: 'can_manage_sensitive_config',
          value: event.target.checked,
        },
      },
    });
    // And invalid me ?? or invalidSession
  };

  const { isSensitive } = useSensitiveModifications('roles');

  if (capabilitiesBaseList && capabilitiesBaseList.edges) {
    return (
      <List dense={true}>
        {isSensitive && !isCapabilitiesInDraft && (
          <ListItem
            key="sensitive"
            divider={true}
            style={{ paddingLeft: 0 }}
            secondaryAction={(
              <Checkbox
                onChange={(event) => handleSensitiveToggle(event)}
                checked={!!role.can_manage_sensitive_config}
                style={{ color: theme.palette.dangerZone.main }}
                disabled={false}
              />
            )}
          >
            <ListItemIcon style={{ minWidth: 32 }}>
              <LocalPoliceOutlined fontSize="small" />
            </ListItemIcon>
            <ListItemText
              primary={(
                <Stack alignItems="center" direction="row" gap={1}>
                  {t_i18n('Allow modification of sensitive configuration')}
                  <DangerZoneChip />
                </Stack>
              )}
            />
          </ListItem>
        )}
        {capabilitiesBaseList.edges.map((edge) => {
          const capability = edge?.node;
          if (capability) {
            const paddingLeft = capability.name.split('_').length * 20 - 20;
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
            return (
              <ListItem
                key={capability.name}
                divider={true}
                style={{ paddingLeft }}
                secondaryAction={capability.name !== SETTINGS && (
                  <Checkbox
                    onChange={(event) => handleToggle(capability.id, event)}
                    checked={isChecked}
                    disabled={isDisabled}
                  />
                )}
              >
                <ListItemIcon style={{ minWidth: 32 }}>
                  <LocalPoliceOutlined fontSize="small" />
                </ListItemIcon>
                <ListItemText primary={t_i18n(capability.description)} />
              </ListItem>
            );
          }
          return <div key="none" />;
        })}
      </List>
    );
  }
  return <Loader variant={LoaderVariant.inline} />;
};

const RoleEditionCapabilities = createFragmentContainer(
  RoleEditionCapabilitiesComponent,
  {
    role: graphql`
      fragment RoleEditionCapabilities_role on Role {
        id
        can_manage_sensitive_config
        capabilities {
          id
          name
          description
        }
        capabilitiesInDraft {
          id
          name
          description
        }
      }
    `,
  },
);

export default RoleEditionCapabilities;
