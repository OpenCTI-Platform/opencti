import makeStyles from '@mui/styles/makeStyles';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import { ClearOutlined, CloseOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import React, { FunctionComponent, useEffect, useState } from 'react';
import Toolbar from '@mui/material/Toolbar';
import Tooltip from '@mui/material/Tooltip';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import Switch from '@mui/material/Switch';
import { useFragment, useMutation } from 'react-relay';
import * as R from 'ramda';
import VisibilityOffIcon from '@mui/icons-material/VisibilityOff';
import MessageIcon from '@mui/icons-material/Message';
import DescriptionIcon from '@mui/icons-material/Description';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { entitySettingFragment, entitySettingsPatch } from './EntitySetting';
import useEntitySettings from '../../../../utils/hooks/useEntitySettings';
import { EntitySetting_entitySetting$data } from './__generated__/EntitySetting_entitySetting.graphql';
import { MESSAGING$ } from '../../../../relay/environment';

const useStyles = makeStyles<Theme>((theme) => ({
  bottomNav: {
    zIndex: 1100,
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  title: {
    flex: '1 1 100%',
    fontSize: '12px',
  },
  titleNumber: {
    padding: '2px 5px 2px 5px',
    marginRight: 5,
    backgroundColor: theme.palette.secondary.main,
    color: '#ffffff',
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
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
  container: {
    padding: '10px 20px 20px 20px',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
}));

const ToolBar: FunctionComponent<{
  keyword: string | undefined
  numberOfSelectedElements: number
  selectedElements: Record<string, { id: string }>
  selectAll: boolean
  handleClearSelectedElements: () => void
}> = ({
  keyword,
  numberOfSelectedElements,
  selectedElements,
  selectAll,
  handleClearSelectedElements,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const entitySettings = useEntitySettings().edges.map((edgeNode) => edgeNode.node)
    .map((node) => useFragment(entitySettingFragment, node) as EntitySetting_entitySetting$data);
  let entitySettingsSelected: EntitySetting_entitySetting$data[];
  if (selectAll) {
    entitySettingsSelected = entitySettings;
  } else {
    entitySettingsSelected = entitySettings.filter((node) => R.values(selectedElements).map((n) => n.id).includes(node.target_type));
  }
  const entitySettingsSelectedFiltered = entitySettingsSelected.filter((node) => {
    if (keyword) {
      return node.target_type.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
        || t(`entity_${node.target_type}`).toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
    }
    return true;
  });

  const [navOpen, setNavOpen] = useState<boolean>(localStorage.getItem('navOpen') === 'true');
  useEffect(() => {
    const subscription = MESSAGING$.toggleNav.subscribe({
      next: () => setNavOpen(localStorage.getItem('navOpen') === 'true'),
    });
    return subscription.unsubscribe;
  });

  const [display, setDisplay] = useState<boolean>(false);
  const [title, setTitle] = useState<string>('');
  const [description, setDescription] = useState<string>('');
  const [value, setValue] = useState<boolean>(false);
  const [key, setKey] = useState<string>('');
  const [notAvailableSetting, setNotAvailableSetting] = useState<EntitySetting_entitySetting$data[]>([]);

  const [commit] = useMutation(entitySettingsPatch);

  const handleOpen = () => setDisplay(true);
  const handleClose = () => {
    setDisplay(false);
    setValue(false);
  };

  const retrieveNotAvailableSetting = (currentKey: string) => {
    return entitySettingsSelectedFiltered.filter((node) => node[currentKey as keyof EntitySetting_entitySetting$data] === null);
  };

  const handleOpenFilesRef = () => {
    handleOpen();
    setTitle(t('Entities automatic reference from files'));
    setDescription(t('This configuration enables an entity to automatically construct an external reference from the uploaded file.'));
    setKey('platform_entity_files_ref');
    setNotAvailableSetting(retrieveNotAvailableSetting('platform_entity_files_ref'));
  };

  const handleOpenHidden = () => {
    handleOpen();
    setTitle(t('Hidden entity types'));
    setDescription(t('This configuration hidde a specific entity type across the entire platform.'));
    setKey('platform_hidden_type');
    setNotAvailableSetting(retrieveNotAvailableSetting('platform_hidden_type'));
  };

  const handleOpenEnforceRef = () => {
    handleOpen();
    setTitle(t('Enforce reference on entity types'));
    setDescription(t('This configuration enables the requirement of a reference message on an entity update.'));
    setKey('enforce_reference');
    setNotAvailableSetting(retrieveNotAvailableSetting('enforce_reference'));
  };

  const handleAction = () => {
    const ids = entitySettingsSelectedFiltered
      .filter((node) => !notAvailableSetting.map((n) => n.target_type).includes(node.target_type))
      .map((node) => node.id);
    commit({
      variables: {
        ids,
        input: { key, value: value.toString() },
      },
    });
    handleClose();
  };

  return (
    <Drawer
      anchor="bottom"
      variant="persistent"
      classes={{ paper: classes.bottomNav }}
      open={numberOfSelectedElements > 0 || selectAll}
      PaperProps={{
        variant: 'elevation',
        elevation: 1,
        style: { paddingLeft: navOpen ? 185 : 60 },
      }}
    >
      <Toolbar style={{ minHeight: 54 }}>
        <Typography
          className={classes.title}
          color="inherit"
          variant="subtitle1"
        >
          <span className={classes.titleNumber}>{numberOfSelectedElements}</span>
          {' '}{t('selected')}{' '}
          <IconButton
            aria-label="clear"
            disabled={numberOfSelectedElements === 0}
            onClick={handleClearSelectedElements}
            size="small"
          >
            <ClearOutlined fontSize="small" />
          </IconButton>
        </Typography>
        <Tooltip title={t('Entities automatic reference from files')}>
          <span>
            <IconButton
              aria-label="files-ref"
              disabled={numberOfSelectedElements === 0 || numberOfSelectedElements === retrieveNotAvailableSetting('platform_entity_files_ref').length}
              onClick={handleOpenFilesRef}
              color="primary"
              size="small"
            >
              <DescriptionIcon fontSize="small" />
            </IconButton>
          </span>
        </Tooltip>
        <Tooltip title={t('Hidden entity types')}>
          <span>
            <IconButton
              aria-label="hidden-entity"
              disabled={numberOfSelectedElements === 0 || numberOfSelectedElements === retrieveNotAvailableSetting('platform_hidden_type').length}
              onClick={handleOpenHidden}
              color="primary"
              size="small"
            >
              <VisibilityOffIcon fontSize="small" />
            </IconButton>
          </span>
        </Tooltip>
        <Tooltip title={t('Enforce reference on entity types')}>
          <span>
            <IconButton
              aria-label="enforce-ref"
              disabled={numberOfSelectedElements === 0 || numberOfSelectedElements === retrieveNotAvailableSetting('enforce_reference').length}
              onClick={handleOpenEnforceRef}
              color="primary"
              size="small"
            >
              <MessageIcon fontSize="small" />
            </IconButton>
          </span>
        </Tooltip>
      </Toolbar>

      <Drawer
        open={display}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}
            size="large"
            color="primary"
          >
            <CloseOutlined fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{title}</Typography>
        </div>
        <div className={classes.container} style={{ marginTop: 20 }}>
          {notAvailableSetting.length > 0
            && <Alert severity="warning" style={{ marginBottom: 20 }}>
              {t(
                `This setting is not available for this entity types: 
                ${notAvailableSetting.map((node) => t(`entity_${node.target_type}`)).join(', ')}`,
              )}
            </Alert>
          }
          <Typography variant="h3" gutterBottom={true} style={{ marginBottom: 20 }}>
            {description}
          </Typography>
          <Switch checked={value} onChange={() => setValue(!value)} />
          <div className={classes.buttons}>
            <Button
              variant="contained"
              color="primary"
              onClick={handleAction}
            >
              {t('Update')}
            </Button>
          </div>
        </div>
      </Drawer>
    </Drawer>
  );
};

export default ToolBar;
