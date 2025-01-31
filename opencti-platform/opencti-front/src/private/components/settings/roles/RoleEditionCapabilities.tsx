import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql, usePreloadedQuery } from 'react-relay';
import * as R from 'ramda';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
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
  }
`;

interface RoleEditionCapabilitiesComponentProps {
  role: RoleEditionCapabilities_role$data;
  queryRef: PreloadedQuery<RoleEditionCapabilitiesLinesSearchQuery>;
}

const RoleEditionCapabilitiesComponent: FunctionComponent<RoleEditionCapabilitiesComponentProps> = ({ role, queryRef }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const { capabilities } = usePreloadedQuery<RoleEditionCapabilitiesLinesSearchQuery>(
    roleEditionCapabilitiesLinesSearch,
    queryRef,
  );
  const roleCapabilities = (role.capabilities ?? []).map((n) => ({
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
            relationship_type: 'has-capability',
          },
        },
      });
    } else {
      commitRemoveCapability({
        variables: {
          id: roleId,
          toId: capabilityId,
          relationship_type: 'has-capability',
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

  if (capabilities && capabilities.edges) {
    return (
      <List dense={true}>
        {isSensitive && (
          <ListItem
            key="sensitive"
            divider={true}
            style={{ paddingLeft: 0 }}
          >
            <ListItemIcon style={{ minWidth: 32 }}>
              <LocalPoliceOutlined fontSize="small" />
            </ListItemIcon>
            <ListItemText
              primary={
                <>
                  {t_i18n('Allow modification of sensitive configuration')}
                  <DangerZoneChip />
                </>
              }
            />
            <ListItemSecondaryAction>
              <Checkbox
                onChange={(event) => handleSensitiveToggle(event)}
                checked={!!role.can_manage_sensitive_config}
                style={{ color: theme.palette.dangerZone.main }}
                disabled={false}
              />
            </ListItemSecondaryAction>
          </ListItem>
        )}
        {capabilities.edges.map((edge) => {
          const capability = edge?.node;
          if (capability) {
            const paddingLeft = capability.name.split('_').length * 20 - 20;
            const roleCapability = roleCapabilities.find(
              (r) => r.name === capability.name,
            );
            const matchingCapabilities = R.filter(
              (r) => capability.name !== r.name
                && R.includes(capability.name, r.name)
                && capability.name !== 'BYPASS',
              roleCapabilities,
            );
            const isDisabled = matchingCapabilities.length > 0;
            const isChecked = isDisabled || roleCapability !== undefined;
            return (
              <ListItem
                key={capability.name}
                divider={true}
                style={{ paddingLeft }}
              >
                <ListItemIcon style={{ minWidth: 32 }}>
                  <LocalPoliceOutlined fontSize="small" />
                </ListItemIcon>
                <ListItemText primary={t_i18n(capability.description)} />
                <ListItemSecondaryAction>
                  {capability.name !== SETTINGS && (
                    <Checkbox
                      onChange={(event) => handleToggle(capability.id, event)}
                      checked={isChecked}
                      disabled={isDisabled}
                    />
                  )}
                </ListItemSecondaryAction>
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
      }
    `,
  },
);

export default RoleEditionCapabilities;
