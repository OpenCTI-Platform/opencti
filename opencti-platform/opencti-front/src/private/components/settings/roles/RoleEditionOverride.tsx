import { FunctionComponent, useState } from "react";
import { PreloadedQuery, createFragmentContainer, graphql, useMutation, usePreloadedQuery } from "react-relay";
import Loader, { LoaderVariant } from "src/components/Loader";
import { useFormatter } from "src/components/i18n";
import { RoleEditionCapabilities_role$data } from "./__generated__/RoleEditionCapabilities_role.graphql";
import { RoleEditionCapabilitiesLinesSearchQuery } from "./__generated__/RoleEditionCapabilitiesLinesSearchQuery.graphql";
import { roleEditionCapabilitiesLinesSearch } from "./RoleEditionCapabilities";
import { Button, Checkbox, IconButton, List, ListItem, ListItemIcon, ListItemSecondaryAction, ListItemText, ListSubheader, MenuItem, Paper, Select } from "@mui/material";
import { LocalPoliceOutlined } from "@mui/icons-material";
import { makeStyles } from "@mui/styles";
import DeleteIcon from '@mui/icons-material/Delete';

const useStyles = makeStyles(() => ({
  paper: {
    height: '25vh',
    overflow: 'auto',
    border: '2px solid white',
    marginBottom: '15px',
    paddingLeft: '10px',
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
        overrides {
          entity
          capabilities {
            name
          }
        }
      }
    }
  }
`;

export const StixDomainObjects = [
  'Reports',
  'Groupings',
  'Malware Analysis',
  'Notes',
  'External References',
  'Incident Responses',
  'Requests for Information',
  'Requests for Takedown',
  'Tasks',
  'Feedbacks',
  'Incidents',
  'Sightings',
  'Observed Data',
  'Observables',
  'Artifacts',
  'Indicators',
  'Infrastructure',
  'Threat Actors (Group)',
  'Threat Actors (Individuals)',
  'Intrusion Sets',
  'Campaigns',
  'Malware',
  'Channels',
  'Tools',
  'Vulnerabilities',
  'Attack Patterns',
  'Narratives',
  'Courses of Actions',
  'Data Components',
  'Data Sources',
  'Sectors',
  'Events',
  'Organizations',
  'Systems',
  'Individuals',
  'Regions',
  'Countries',
  'Areas',
  'Cities',
  'Positions',
]

interface RoleEditionOverrideComponentProps {
  role: RoleEditionCapabilities_role$data;
  queryRef: PreloadedQuery<RoleEditionCapabilitiesLinesSearchQuery>;
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
  capabilities: Capability[]
) => {
  if (existing.filter(e => e.entity === entity).length > 0) return existing;
  const result = [
    ...existing,
    {
      entity,
      capabilities,
    }
  ];
  return result;
};

const addCapabilityUnique = (
  existing: Capability[],
  capability: Capability,
) => {
  if (existing.filter(e => e.name === capability.name).length > 0) return existing;
  return [
    ...existing,
    capability,
  ];
};

const RoleEditionOverrideComponent: FunctionComponent<
  RoleEditionOverrideComponentProps
> = ({ role, queryRef }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const { capabilities } = usePreloadedQuery<RoleEditionCapabilitiesLinesSearchQuery>(
    roleEditionCapabilitiesLinesSearch,
    queryRef,
  );

  const [commitEditOverrides] = useMutation(roleEditionEditOverrides);
  const overrides = role.overrides;
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
          {t('Override capabilities for ')}
          <Select
            style={{ width: '30%' }}
            value={selected}
            onChange={({ target: { value }}) => {setSelected(value)}}
          >
            {StixDomainObjects.map(((sdo: string, i: number) => (
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
            onClick={() =>
              commitEditOverrides({
                variables: {
                  id: role.id,
                  input: [{
                    key: 'overrides',
                    value: addOverrideUnique(
                      role.overrides as RoleEntityOverride[] ?? [],
                      selected,
                      role.capabilities as Capability[] ?? []
                    ),
                    operation: overrides ? 'replace' : 'add',
                  }],
                }
              })
            }
            disabled={selected === ''}
          >
            Add
          </Button>
        </ListSubheader>
        {overrides?.map((override) => (
          <Paper className={classes.paper}>
            <span className={classes.banner}>
              <p className={classes.subheader}>
                {override?.entity} entity type capabilities
              </p>
              <IconButton onClick={() => 
                commitEditOverrides({
                  variables: {
                    id: role.id,
                    input: [{
                      key: 'overrides',
                      value: role.overrides?.filter(o => o?.entity !== override?.entity),
                      operation: 'replace',
                    }]
                  }
                })
              }>
                <DeleteIcon />
              </IconButton>
            </span>
            <List dense={true}>
              {capabilities.edges?.map((edge) => {
                const capability = edge?.node;
                if (capability) {
                  if ((role.capabilities?.filter(c => c?.name === capability.name) ?? []).length < 1) { return <div key={'none'}></div>; }
                  const paddingLeft = capability.name.split('_').length * 20 - 20;
                  const roleCapability = override?.capabilities?.find((r) => r?.name === capability.name);
                  const matchingCapabilities = override?.capabilities?.filter(
                    (r) => capability.name !== r?.name
                      && r?.name.includes(capability.name)
                      && capability.name !== 'BYPASS'
                  );
                  const isDisabled = matchingCapabilities && matchingCapabilities.length > 0;
                  const isChecked = isDisabled || roleCapability !== undefined;

                  return (
                    <ListItem
                      key={capability.name}
                      divider={true}
                      style={{
                        paddingLeft,
                        flex: 1,
                        overflowY: 'scroll',
                      }}
                    >
                      <ListItemIcon style={{ minWidth: 32 }}>
                        <LocalPoliceOutlined fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={t(capability.description)} />
                      <ListItemSecondaryAction>
                        <Checkbox
                          onChange={(event) => {
                            const setChecked = event.target.checked;
                            commitEditOverrides({
                              variables: {
                                id: role.id,
                                input: [{
                                  key: 'overrides',
                                  value: role.overrides?.map(o => o?.entity !== override?.entity ? o :
                                    ({
                                      entity: o?.entity,
                                      capabilities: setChecked
                                        ? addCapabilityUnique(override?.capabilities as Capability[], capability as Capability)
                                        : override?.capabilities?.filter(c => c?.name !== capability.name),
                                    })),
                                  operation: 'replace',
                                }],
                              },
                            })
                          }}
                          checked={isChecked}
                          disabled={isDisabled}
                        />
                      </ListItemSecondaryAction>
                    </ListItem>
                  );
                }
                return <div key={'none'} />;
              })}
            </List>
          </Paper>
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
        overrides {
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