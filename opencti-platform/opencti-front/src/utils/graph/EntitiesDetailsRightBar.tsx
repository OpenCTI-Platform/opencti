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
import EntityDetails from './EntityDetails';
import RelationshipDetails from './RelationshipDetails';
import { useFormatter } from '../../components/i18n';

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
    padding: '60px 0 20px 20px',
    zIndex: 900,
  },
  external: {
    marginTop: -2,
    paddingLeft: 10,
  },
}));

export interface SelectedEntity {
  id: string;
  label: string;
  relationship_type?: string;
  entity_type: string;
  source?: SelectedEntity;
  target?: SelectedEntity;
  fromId?: string;
  fromType?: string;
  toId?: string;
  toType?: string;
}

interface EntityDetailsRightsBarProps {
  selectedEntities: SelectedEntity[];
}
const EntitiesDetailsRightsBar: FunctionComponent<
EntityDetailsRightsBarProps
> = ({ selectedEntities }) => {
  const classes = useStyles();
  const theme = useTheme<Theme>();
  const { t } = useFormatter();
  const uniqSelectedEntities: SelectedEntity[] = selectedEntities
    .filter(
      (item, index) => selectedEntities.findIndex((entity) => entity.id === item.id) === index,
    )
    .map((n) => {
      if (n.source && n.target) {
        const source = n.source.label;
        const target = n.target.label;
        return { ...n, label: `${source} ➡️ ${target}` };
      }
      if (n.fromType && n.toType) {
        const source = n.fromType;
        const target = n.toType;
        return { ...n, label: `${source} ➡️ ${target}` };
      }
      return n;
    });
  const [selectedEntity, setSelectedEntity] = useState<SelectedEntity>(
    uniqSelectedEntities[0],
  );
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
  return (
    <Drawer
      open={true}
      variant="permanent"
      anchor="right"
      classes={{ paper: classes.drawerPaper }}
      PaperProps={{ variant: 'outlined' }}
      transitionDuration={theme.transitions.duration.enteringScreen}
    >
      <div
        style={{
          display: 'flex',
          position: 'fixed',
          left: 20,
          top: 20,
          width: 360,
        }}
      >
        <FormControl fullWidth={true} size="small" style={{ flex: 'grow' }}>
          <InputLabel id="label">{t('Object')}</InputLabel>
          <Select
            labelId="label"
            label={t('Object')}
            fullWidth={true}
            onChange={handleSelectEntity}
            value={selectedEntity.id}
          >
            {uniqSelectedEntities.map((entity) => (
              <MenuItem key={entity.id} value={entity.id}>
                {entity.label}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <div className={classes.external}>
          <IconButton
            component={Link}
            target="_blank"
            to={`/dashboard/id/${selectedEntity.id}`}
            size="medium"
          >
            <OpenInNewOutlined fontSize="medium" />
          </IconButton>
        </div>
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
        {selectedEntity.relationship_type ? (
          <RelationshipDetails relation={selectedEntity} />
        ) : (
          <EntityDetails entity={selectedEntity} />
        )}
      </div>
    </Drawer>
  );
};
export default EntitiesDetailsRightsBar;
