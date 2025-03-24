import React, { FunctionComponent, useEffect, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Drawer from '@mui/material/Drawer';
import { Theme } from '@mui/material/styles/createTheme';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import { useTheme } from '@mui/styles';
import IconButton from '@mui/material/IconButton';
import { Link } from 'react-router-dom';
import { OpenInNewOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { Typography } from '@mui/material';
import EntityDetails from './EntityDetails';
import RelationshipDetails from './RelationshipDetails';
import { useFormatter } from '../../i18n';
import { isStixNestedRefRelationship } from '../../../utils/Relation';
import StixMetaObjectDetails from './StixMetaObjectDetails';
import BasicRelationshipDetails from './BasicRelationshipDetails';
import { GraphLink, GraphNode, isGraphLink, isGraphNode } from '../graph.types';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  drawerPaper: {
    position: 'fixed',
    top: '50%',
    right: 20,
    transform: 'translateY(-50%)',
    width: 400,
    maxWidth: 400,
    height: '60%',
    maxHeight: '60%',
    padding: '20px 0 20px 20px',
    zIndex: 900,
    borderRadius: 4,
  },
  external: {
    marginTop: -2,
    paddingLeft: 10,
  },
}));

interface EntityDetailsRightsBarProps {
  selectedEntities: (GraphNode | GraphLink)[];
}
const EntitiesDetailsRightsBar: FunctionComponent<
EntityDetailsRightsBarProps
> = ({ selectedEntities }) => {
  const classes = useStyles();
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const uniqSelectedEntities = selectedEntities
    .map((n) => {
      if (
        isGraphLink(n)
        && n.source && typeof n.source !== 'string'
        && n.target && typeof n.target !== 'string'
      ) {
        const source = n.source.label;
        const target = n.target.label;
        return { ...n, label: `${source} ➡️ ${target}` };
      }
      if (isGraphNode(n) && n.fromType && n.toType) {
        const source = n.fromType;
        const target = n.toType;
        return { ...n, label: `${source} ➡️ ${target}` };
      }
      return n;
    });
  const [selectedEntity, setSelectedEntity] = useState(uniqSelectedEntities[0]);
  useEffect(() => {
    if (uniqSelectedEntities[0] !== selectedEntity) {
      setSelectedEntity(uniqSelectedEntities[0]);
    }
  }, [selectedEntities]);
  const handleSelectEntity = (event: SelectChangeEvent) => {
    const { value } = event.target;
    const entity = selectedEntities.find((el) => el.id === value);
    if (!entity) {
      setSelectedEntity(uniqSelectedEntities[0]);
    } else {
      setSelectedEntity(entity);
    }
  };
  const hasOverviewPage = !selectedEntity.parent_types.some((el) => isStixNestedRefRelationship(el))
    && (!selectedEntity.parent_types.includes('Stix-Meta-Object')
      || selectedEntity.entity_type === 'External-Reference')
    && selectedEntity.entity_type !== 'basic-relationship';
  const entityUrl = selectedEntity.entity_type === 'External-Reference'
    ? `/dashboard/analyses/external_references/${selectedEntity.id}`
    : `/dashboard/id/${selectedEntity.id}`;
  return (
    <Drawer
      open={true}
      variant="permanent"
      anchor="right"
      classes={{ paper: classes.drawerPaper }}
      PaperProps={{ variant: 'outlined' }}
      transitionDuration={theme.transitions.duration.enteringScreen}
    >
      <Typography variant='h3' sx={{ marginBottom: 3 }}>
        {t_i18n('', {
          id: 'objects selected',
          values: {
            count: uniqSelectedEntities.length,
          },
        })}
      </Typography>
      <div style={{ display: 'flex' }}>
        <FormControl fullWidth={true} size="small" style={{ flex: 'grow' }}>
          <InputLabel id="label" variant="outlined">
            {t_i18n('Object')}
          </InputLabel>
          <Select
            labelId="label"
            label={t_i18n('Object')}
            fullWidth={true}
            onChange={handleSelectEntity}
            value={selectedEntity.id}
            variant="outlined"
          >
            {uniqSelectedEntities.map((entity) => (
              <MenuItem key={entity.id} value={entity.id}>
                {entity.label}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        {/* Need to be handled */}
        {hasOverviewPage && (
          <Tooltip title={t_i18n('Open the entity overview in a separated tab')}>
            <div className={classes.external}>
              <IconButton
                component={Link}
                target="_blank"
                to={entityUrl}
                size="medium"
              >
                <OpenInNewOutlined fontSize="medium" />
              </IconButton>
            </div>
          </Tooltip>
        )}
      </div>
      <div className="clearfix" />
      <div
        style={{
          height: '100%',
          maxHeight: '100%',
          overflowY: 'auto',
          paddingRight: 20,
        }}
      >
        {selectedEntity.entity_type === 'basic-relationship' && (
          <BasicRelationshipDetails relation={selectedEntity as GraphLink} />
        )}
        {selectedEntity.parent_types.includes('stix-relationship')
          && selectedEntity.entity_type !== 'basic-relationship' && (
            <RelationshipDetails relation={selectedEntity as GraphLink} />
        )}
        {selectedEntity.parent_types.includes('Stix-Core-Object') && (
          <EntityDetails entity={selectedEntity as GraphNode} />
        )}
        {selectedEntity.parent_types.includes('Stix-Meta-Object') && (
          <StixMetaObjectDetails entity={selectedEntity as GraphNode} />
        )}
      </div>
    </Drawer>
  );
};
export default EntitiesDetailsRightsBar;
