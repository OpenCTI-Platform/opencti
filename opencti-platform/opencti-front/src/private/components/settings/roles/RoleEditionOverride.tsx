import React, { FunctionComponent, useState } from 'react';
import { PreloadedQuery, createFragmentContainer, graphql, useMutation, usePreloadedQuery } from 'react-relay';
import Loader, { LoaderVariant } from 'src/components/Loader';
import { useFormatter } from 'src/components/i18n';
import { Button, Checkbox, IconButton, List, ListItem, ListItemIcon, ListItemSecondaryAction, ListItemText, ListSubheader, MenuItem, Select } from '@mui/material';
import { LocalPoliceOutlined } from '@mui/icons-material';
import { makeStyles } from '@mui/styles';
import DeleteIcon from '@mui/icons-material/Delete';
import usePreloadedFragment from 'src/utils/hooks/usePreloadedFragment';
import { overridableCapabilities, roleEditionCapabilitiesLinesSearch } from './RoleEditionCapabilities';
import { RoleEditionCapabilitiesLinesSearchQuery } from './__generated__/RoleEditionCapabilitiesLinesSearchQuery.graphql';
import { RoleEditionCapabilities_role$data } from './__generated__/RoleEditionCapabilities_role.graphql';
import { SubTypesLinesQuery } from '../sub_types/__generated__/SubTypesLinesQuery.graphql';
import { subTypesLinesFragment, subTypesLinesQuery } from '../sub_types/SubTypesLines';
import { SubTypesLines_subTypes$key } from '../sub_types/__generated__/SubTypesLines_subTypes.graphql';

const useStyles = makeStyles(() => ({
  section: {
    display: 'flex',
    flexDirection: 'column',
  },
  banner: {
    paddingRight: '16px',
    display: 'inline-flex',
    justifyContent: 'space-between',
  },
  subheader: {
    display: 'inline-block',
    margin: '8px 0px',
  },
  addButton: {
    float: 'right',
    padding: '4px 10px',
    margin: '5px 0px',
  },
}));

const roleEditionEditOverrides = graphql`
  mutation RoleEditionOverrideAddOverrideMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    roleEdit(id: $id) {
      fieldPatch(input: $input) {
        capabilities_overrides {
          entity
          capabilities {
            name
          }
        }
      }
    }
  }
`;

interface RoleEditionOverrideComponentProps {
  role: RoleEditionCapabilities_role$data;
  queryRef: PreloadedQuery<RoleEditionCapabilitiesLinesSearchQuery>;
  subTypesQueryRef: PreloadedQuery<SubTypesLinesQuery>;
}

interface Capability {
  name: string,
  description: string,
  id: string,
}

interface RoleEntityOverride {
  entity: string,
  capabilities: Capability[],
}

const addOverrideUnique = (
  existing: RoleEntityOverride[],
  entity: string,
  capabilities: Capability[],
) => {
  if (existing.filter((e) => e.entity === entity).length > 0) return existing;
  const result = [
    ...existing,
    {
      entity,
      capabilities: capabilities.filter((c) => overridableCapabilities.includes(c.name)),
    },
  ];
  return result;
};

const addCapabilityUnique = (
  existing: Capability[],
  capability: Capability,
) => {
  if (existing.filter((e) => e.name === capability.name).length > 0) return existing;
  return [
    ...existing,
    capability,
  ];
};

const RoleEditionOverrideComponent: FunctionComponent<
RoleEditionOverrideComponentProps
> = ({ role, queryRef, subTypesQueryRef }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { capabilities } = usePreloadedQuery<RoleEditionCapabilitiesLinesSearchQuery>(
    roleEditionCapabilitiesLinesSearch,
    queryRef,
  );
  const subTypesData = usePreloadedFragment<
  SubTypesLinesQuery,
  SubTypesLines_subTypes$key
  >({
    queryDef: subTypesLinesQuery,
    fragmentDef: subTypesLinesFragment,
    queryRef: subTypesQueryRef,
  });
  const subTypes = subTypesData.subTypes.edges
    .filter(({ node }) => node.overridable)
    .map(({ node }) => node.label);

  const [commitEditOverrides] = useMutation(roleEditionEditOverrides);
  const { capabilities_overrides } = role;
  const [selected, setSelected] = useState<string>('');

  if (capabilities?.edges) {
    return (
      <div>
        <ListSubheader
          component="div"
          sx={{
            paddingLeft: 0,
            backgroundColor: 'transparent',
          }}
        >
          {t_i18n('Override capabilities for ')}
          <Select
            style={{ width: '30%' }}
            value={selected}
            onChange={({ target: { value } }) => { setSelected(value); }}
          >
            {subTypes.map(((sdo: string, i: number) => (
              <MenuItem
                key={i}
                value={sdo}
              >
                {sdo}
              </MenuItem>
            )))}
          </Select>
          <Button
            variant="contained"
            color="secondary"
            className={classes.addButton}
            onClick={() => commitEditOverrides({
              variables: {
                id: role.id,
                input: [{
                  key: 'capabilities_overrides',
                  value: addOverrideUnique(
                    role.capabilities_overrides as RoleEntityOverride[] ?? [],
                    selected,
                    role.capabilities as Capability[] ?? [],
                  ),
                  operation: capabilities_overrides ? 'replace' : 'add',
                }],
              },
            })
            }
            disabled={selected === ''}
          >
            Add
          </Button>
        </ListSubheader>
        {capabilities_overrides?.map((override, i) => (
          <div className={classes.section} key={i}>
            <span className={classes.banner}>
              <p className={classes.subheader}>
                {override?.entity} entity type capabilities
              </p>
              <IconButton onClick={() => commitEditOverrides({
                variables: {
                  id: role.id,
                  input: [{
                    key: 'capabilities_overrides',
                    value: role.capabilities_overrides?.filter((o) => o?.entity !== override?.entity),
                    operation: 'replace',
                  }],
                },
              })
              }
              >
                <DeleteIcon />
              </IconButton>
            </span>
            <List dense={true}>
              {capabilities.edges?.map((edge) => {
                const capability = edge?.node;
                if (capability) {
                  if (!overridableCapabilities.includes(capability.name)) { return <div key={i}></div>; }
                  const paddingLeft = capability.name.split('_').length * 20 - 20;
                  const roleCapability = override?.capabilities?.find((r) => r?.name === capability.name);
                  const matchingCapabilities = override?.capabilities?.filter(
                    (r) => capability.name !== r?.name
                      && r?.name.includes(capability.name)
                      && capability.name !== 'BYPASS',
                  );
                  const isDisabled = matchingCapabilities && matchingCapabilities.length > 0;
                  const isChecked = isDisabled || roleCapability !== undefined;

                  return (
                    <ListItem
                      key={capability.name}
                      divider={true}
                      style={{
                        paddingLeft,
                      }}
                    >
                      <ListItemIcon style={{ minWidth: 32 }}>
                        <LocalPoliceOutlined fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={t_i18n(capability.description)} />
                      <ListItemSecondaryAction>
                        <Checkbox
                          onChange={(event) => {
                            const setChecked = event.target.checked;
                            commitEditOverrides({
                              variables: {
                                id: role.id,
                                input: [{
                                  key: 'capabilities_overrides',
                                  value: role.capabilities_overrides?.map((o) => (o?.entity !== override?.entity ? o
                                    : ({
                                      entity: o?.entity,
                                      capabilities: setChecked
                                        ? addCapabilityUnique(override?.capabilities as Capability[] ?? [], capability as Capability)
                                        : override?.capabilities?.filter((c) => c?.name !== capability.name),
                                    }))),
                                  operation: 'replace',
                                }],
                              },
                            });
                          }}
                          checked={isChecked}
                          disabled={isDisabled}
                        />
                      </ListItemSecondaryAction>
                    </ListItem>
                  );
                }
                return <div key={i} />;
              })}
            </List>
            <hr style={{ width: '100%' }} />
          </div>
        ))}
      </div>
    );
  }

  return <Loader variant={LoaderVariant.inElement} />;
};

const RoleEditionOverride = createFragmentContainer(
  RoleEditionOverrideComponent,
  {
    role: graphql`
      fragment RoleEditionOverride_role on Role {
        id
        capabilities {
          id
          name
          description
        }
        capabilities_overrides {
          entity
          capabilities {
            id
            name
            description
          }
        }
      }
    `,
  },
);

export default RoleEditionOverride;
