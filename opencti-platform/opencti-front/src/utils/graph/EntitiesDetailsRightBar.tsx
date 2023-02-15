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
import EntityDetails from './EntityDetails';

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

interface selectedNode {
  id: string
  name: string
  label: string
}
interface EntityDetailsRightsBarProps {
  selectedNodes: selectedNode[];
  open: boolean
  handleClose?: () => void
}
const EntitiesDetailsRightsBar: FunctionComponent<EntityDetailsRightsBarProps> = ({ selectedNodes, open, handleClose }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [controlOpen, setControlOpen] = useState<boolean>(open ?? false);
  const handleControlClose = () => setControlOpen(false);

  let entityId: string;

  const onEntityChange = (event: SelectChangeEvent) => {
    entityId = event.target.value;
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
          <EntityDetails
            id={node.id}
          />
        ))}

    </Drawer>
  );
};
export default EntitiesDetailsRightsBar;
