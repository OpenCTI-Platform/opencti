import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Drawer from '@mui/material/Drawer';
import { Theme } from '@mui/material/styles/createTheme';
import List from '@mui/material/List';
import ListSubheader from '@mui/material/ListSubheader';
import ListItemText from '@mui/material/ListItemText';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { Link } from 'react-router-dom';
import { InfoOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import * as R from 'ramda';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import { useFormatter } from '../../components/i18n';
import { resolveLink } from '../Entity';
import { Option } from '../../private/components/common/form/ReferenceField';
import ItemAuthor from '../../components/ItemAuthor';
import useQueryLoading from '../hooks/useQueryLoading';
import { EntityDetailsRightBarQuery } from './__generated__/EntityDetailsRightBarQuery.graphql';
import Loader, { LoaderVariant } from '../../components/Loader';

const useStyles = makeStyles < Theme >((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 250,
    padding: '0 20px 20px 20px',
    position: 'fixed',
    zIndex: 900,
  },
  formControl: {
    width: '100%',
    marginTop: '60px',
  },
  item: {
    padding: '0 0 0 6px',
  },
  toolbar: theme.mixins.toolbar,
}));

const entityDetailsRightBarQuery = graphql`
    query EntityDetailsRightBarQuery($id: String!) {
      stixCoreObject(id: $id) {
        id
        entity_type
        parent_types
        created_at
        createdBy {
            ... on Identity {
                id
                name
                entity_type
            }
        }
        objectMarking {
            edges {
                node {
                    id
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                }
            }
        }
        ... on StixDomainObject {
            created
        }
        ... on AttackPattern {
            name
            x_mitre_id
        }
        ... on Campaign {
            name
            first_seen
            last_seen
        }
        ... on CourseOfAction {
            name
        }
        ... on Note {
            attribute_abstract
            content
        }
        ... on ObservedData {
            name
            first_observed
            last_observed
        }
        ... on Opinion {
            opinion
        }
        ... on Report {
            name
            published
        }
        ... on Grouping {
            name
            description
        }
        ... on Individual {
            name
        }
        ... on Organization {
            name
        }
        ... on Sector {
            name
        }
        ... on System {
            name
        }
        ... on Indicator {
            name
            valid_from
        }
        ... on Infrastructure {
            name
        }
        ... on IntrusionSet {
            name
            first_seen
            last_seen
        }
        ... on Position {
            name
        }
        ... on City {
            name
        }
        ... on AdministrativeArea {
            name
        }
        ... on Country {
            name
        }
        ... on Region {
            name
        }
        ... on Malware {
            name
            first_seen
            last_seen
        }
        ... on ThreatActor {
            name
            first_seen
            last_seen
        }
        ... on Tool {
            name
        }
        ... on Vulnerability {
            name
        }
        ... on Incident {
            name
            first_seen
            last_seen
        }
        ... on StixCyberObservable {
            observable_value
        }
        ... on StixFile {
            observableName: name
        }
        ... on Event {
            name
        }
        ... on Case {
            name
        }
        ... on Narrative {
            name
        }
        ... on DataComponent {
            name
        }
        ... on DataSource {
            name
        }
        ... on Language {
            name
        }
      }
    }
`;

interface selectedNode {
  id: string
  name: string
  description: string
  parent_types: string
  relationship_type: string
  fromType: string
  fromId: string
  entity_type: string
  label: string
  createdBy: Option
  objectMarking?: Option[]
  defaultDate: string
  confidence?:string

}
interface EntityDetailsRightsBarProps {
  selectedNodes: selectedNode[];
  open: boolean
  handleClose?: () => void
  queryRef: PreloadedQuery<EntityDetailsRightBarQuery>
}
const EntityDetailsRightsBarComponent: FunctionComponent<EntityDetailsRightsBarProps> = ({ queryRef, selectedNodes, open, handleClose }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [controlOpen, setControlOpen] = useState<boolean>(open ?? false);
  const handleControlClose = () => setControlOpen(false);

  /*
  const entity = usePreloadedQuery<EntityDetailsRightBarQuery>(entityDetailsRightBarQuery, queryRef);
  console.log('selectedNodes', selectedNodes);
  console.log('entity:    ', entity);
*/

  const viewLink = (node: selectedNode) => {
    if (
      !node.parent_types.includes(
        'stix-cyber-observable-relationship',
      )
      && node.relationship_type
    ) {
      return `${resolveLink(node.fromType)}/${
        node.fromId
      }/knowledge/relations/${node.id}`;
    }
    return `${resolveLink(node.entity_type)}/${
      node.id
    }`;
  };

  let entityId: string;

  const onEntityChange = (event: SelectChangeEvent) => {
    entityId = event.target.value;
  };

  const entityDetails = (node: selectedNode) => {
    return (
      <div>
        <Typography
          variant="h3"
          gutterBottom={false}
          style={{ marginTop: 10 }}
        >
          {node.label}
          <Tooltip title={t('View the item')}>
                  <span>
                    <IconButton
                      color="primary"
                      component={Link}
                      to={viewLink(node)}
                      disabled={!viewLink(node)}
                      size="large"
                    >
                      <InfoOutlined />
                    </IconButton>
                  </span>
          </Tooltip>
        </Typography>
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 15 }}
        >
          {t('Type')}
        </Typography>
        {node.entity_type}
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 15 }}
        >
          {t('Description')}
        </Typography>
        {node.description}
        <Typography variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 15 }}
        >
          {t('Marking')}
        </Typography>
        {'Entity marking'}
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 15 }}
        >
          {t('Author')}
        </Typography>
        <ItemAuthor
          createdBy={R.propOr(null, 'createdBy', node)}
        />
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 15 }}
        >
          {t('Id')}
        </Typography>
        <ListItemText primary={node.id} />
      </div>
    );
  };

  return (
    <Drawer
      open={handleClose ? open : controlOpen}
      variant="permanent"
      anchor="right"
      classes={{ paper: classes.drawerPaper }}
      onClose={handleClose ?? handleControlClose }
    >
      <div className={classes.toolbar} />
      <FormControl
        className={classes.formControl}
        fullWidth={true}
        style={{
          flex: 1,
        }}
      >
        <InputLabel id="entityField">
          {t('Selected entities')}
        </InputLabel>
        <Select
          labelId="entityField"
          fullWidth={true}
          onChange={onEntityChange}
        >
          {selectedNodes.map((node) => (
            <MenuItem key={node.label} value={node.id}>
              {node.label}
            </MenuItem>
          ))}
        </Select>
      </FormControl>
        {selectedNodes.map((node) => (
          entityDetails(node)
        ))}

    </Drawer>
  );
};

const EntityDetailsRightsBar: FunctionComponent<Omit<EntityDetailsRightsBarProps, 'queryRef'>> = (
  props,
) => {
  const nodeId = '946cc606-2f09-49bf-97b5-2b57847ff07a';
  const queryRef = useQueryLoading<EntityDetailsRightBarQuery>(entityDetailsRightBarQuery, { id: nodeId });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <EntityDetailsRightsBarComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default EntityDetailsRightsBar;
