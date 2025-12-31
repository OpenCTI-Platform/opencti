import React, { useEffect, useMemo } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Drawer from '@mui/material/Drawer';
import { Theme } from '@mui/material/styles/createTheme';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import { useTheme } from '@mui/styles';
import IconButton from '@common/button/IconButton';
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
import { useGraphContext } from '../GraphContext';
import useGraphInteractions from '../utils/useGraphInteractions';

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

const EntitiesDetailsRightsBar = () => {
  const classes = useStyles();
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { selectDetailsPreviewObject } = useGraphInteractions();

  const {
    graphState: {
      selectedNodes,
      selectedLinks,
      detailsPreviewSelected,
    },
  } = useGraphContext();

  const selectedEntities = useMemo(() => {
    return [...selectedLinks, ...selectedNodes];
  }, [selectedLinks, selectedNodes]);

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

  useEffect(() => {
    if (uniqSelectedEntities[0].id !== detailsPreviewSelected?.id) {
      selectDetailsPreviewObject(uniqSelectedEntities[0]);
    }
  }, [selectedEntities]);

  const handleSelectEntity = (event: SelectChangeEvent) => {
    const { value } = event.target;
    const entity = selectedEntities.find((el) => el.id === value);
    if (!entity) {
      selectDetailsPreviewObject(uniqSelectedEntities[0]);
    } else {
      selectDetailsPreviewObject(entity);
    }
  };

  if (!detailsPreviewSelected) {
    return null;
  }

  const hasOverviewPage = !detailsPreviewSelected.parent_types.some((el) => isStixNestedRefRelationship(el))
    && (!detailsPreviewSelected.parent_types.includes('Stix-Meta-Object')
      || detailsPreviewSelected.entity_type === 'External-Reference')
    && detailsPreviewSelected.entity_type !== 'basic-relationship';

  const entityUrl = detailsPreviewSelected.entity_type === 'External-Reference'
    ? `/dashboard/analyses/external_references/${detailsPreviewSelected.id}`
    : `/dashboard/id/${detailsPreviewSelected.id}`;

  return (
    <Drawer
      open={true}
      variant="permanent"
      anchor="right"
      classes={{ paper: classes.drawerPaper }}
      PaperProps={{ variant: 'outlined' }}
      transitionDuration={theme.transitions.duration.enteringScreen}
    >
      <Typography variant="h3" sx={{ marginBottom: 3 }}>
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
            value={detailsPreviewSelected.id}
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
        {detailsPreviewSelected.entity_type === 'basic-relationship' && (
          <BasicRelationshipDetails relation={detailsPreviewSelected as GraphLink} />
        )}
        {detailsPreviewSelected.parent_types.includes('stix-relationship')
          && detailsPreviewSelected.entity_type !== 'basic-relationship' && (
          <RelationshipDetails relation={detailsPreviewSelected as GraphLink} />
        )}
        {detailsPreviewSelected.parent_types.includes('Stix-Core-Object') && (
          <EntityDetails entity={detailsPreviewSelected as GraphNode} />
        )}
        {detailsPreviewSelected.parent_types.includes('Stix-Meta-Object') && (
          <StixMetaObjectDetails entity={detailsPreviewSelected as GraphNode} />
        )}
      </div>
    </Drawer>
  );
};
export default EntitiesDetailsRightsBar;
