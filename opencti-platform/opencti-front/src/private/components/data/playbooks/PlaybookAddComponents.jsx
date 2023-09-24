import React, { useState } from 'react';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import { Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import * as R from 'ramda';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { isEmptyField } from '../../../../utils/utils';

const useStyles = makeStyles((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    padding: 0,
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  title: {
    float: 'left',
  },
  search: {
    float: 'right',
  },
  lines: {
    padding: 0,
    height: '100%',
    width: '100%',
  },
}));

const PlaybookAddComponents = ({
  open,
  handleClose,
  selectedNode,
  playbookComponents,
  onConfig,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [searchTerm, setSearchTerm] = useState('');
  const [componentId, setComponentId] = useState(
    selectedNode?.data?.component?.id ?? null,
  );
  const onSelect = (component) => {
    if (!isEmptyField(JSON.parse(component.configuration_schema))) {
      setComponentId(component.id);
    } else {
      onConfig(component);
    }
  };
  const renderLines = () => {
    const filterByKeyword = (n) => searchTerm === ''
      || n.name.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || n.description.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1;
    const components = R.pipe(
      R.filter(
        (n) => n.is_entry_point === selectedNode?.data?.isEntryPoint ?? false,
      ),
      R.filter(filterByKeyword),
    )(playbookComponents);
    return (
      <div className={classes.lines}>
        <List>
          {components.map((component) => {
            return (
              <ListItem
                key={component.id}
                divider={true}
                button={true}
                clases={{ root: classes.item }}
                onClick={() => onSelect(component)}
              >
                <ListItemText
                  primary={component.name}
                  secondary={component.description}
                />
              </ListItem>
            );
          })}
        </List>
      </div>
    );
  };
  const renderConfig = () => {
    const selectedComponent = playbookComponents
      .filter((n) => n.id === componentId)
      .at(0);
    return <div className={classes.config}>Config!</div>;
  };
  return (
    <Drawer
      open={open}
      anchor="right"
      elevation={1}
      sx={{ zIndex: 1202 }}
      classes={{ paper: classes.drawerPaper }}
      onClose={() => handleClose()}
    >
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={() => handleClose()}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6" classes={{ root: classes.title }}>
          {t('Add components')}
        </Typography>
        <div className={classes.search}>
          <SearchInput
            variant="inDrawer"
            placeholder={`${t('Search')}...`}
            onChange={setSearchTerm}
          />
        </div>
      </div>
      {componentId === null && renderLines()}
      {componentId !== null && renderConfig()}
    </Drawer>
  );
};

export default PlaybookAddComponents;
