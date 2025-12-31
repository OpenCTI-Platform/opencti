import makeStyles from '@mui/styles/makeStyles';
import Drawer from '@mui/material/Drawer';
import IconButton from '@common/button/IconButton';
import { ClearOutlined, FileOpenOutlined, LocalOfferOutlined, VisibilityOffOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import React, { FunctionComponent, useEffect, useState } from 'react';
import Toolbar from '@mui/material/Toolbar';
import Tooltip from '@mui/material/Tooltip';
import Alert from '@mui/material/Alert';
import Button from '@common/button/Button';
import Switch from '@mui/material/Switch';
import * as R from 'ramda';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormGroup from '@mui/material/FormGroup';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { entitySettingPatch } from './entity_setting/EntitySettingSettings';
import useEntitySettings from '../../../../utils/hooks/useEntitySettings';
import type { EntitySetting } from '../../../../utils/hooks/useEntitySettings';
import { MESSAGING$ } from '../../../../relay/environment';
import useAuth from '../../../../utils/hooks/useAuth';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  bottomNav: {
    zIndex: 1,
    display: 'flex',
    height: 50,
    overflow: 'hidden',
    padding: '0 230px 0 0',
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
}));

const ToolBar: FunctionComponent<{
  keyword: string | undefined;
  numberOfSelectedElements: number;
  selectedElements: Record<string, { id: string }>;
  selectAll: boolean;
  handleClearSelectedElements: () => void;
}> = ({
  keyword,
  numberOfSelectedElements,
  selectedElements,
  selectAll,
  handleClearSelectedElements,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const entitySettings = useEntitySettings();
  const { bannerSettings: { bannerHeightNumber } } = useAuth();
  let entitySettingsSelected;
  if (selectAll) {
    entitySettingsSelected = entitySettings;
  } else {
    entitySettingsSelected = entitySettings.filter((node) => R.values(selectedElements)
      .map((n) => n.id)
      .includes(node.target_type));
  }
  const entitySettingsSelectedFiltered = entitySettingsSelected.filter(
    (node) => {
      if (keyword) {
        return (
          node.target_type.toLowerCase().indexOf(keyword.toLowerCase())
          !== -1
          || t_i18n(`entity_${node.target_type}`)
            .toLowerCase()
            .indexOf(keyword.toLowerCase()) !== -1
        );
      }
      return true;
    },
  );
  const [navOpen, setNavOpen] = useState<boolean>(
    localStorage.getItem('navOpen') === 'true',
  );
  useEffect(() => {
    const subscription = MESSAGING$.toggleNav.subscribe({
      next: () => setNavOpen(localStorage.getItem('navOpen') === 'true'),
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  });
  const [display, setDisplay] = useState<boolean>(false);
  const [title, setTitle] = useState<string>('');
  const [description, setDescription] = useState<string>('');
  const [value, setValue] = useState<boolean>(false);
  const [key, setKey] = useState<string>('');
  const [notAvailableSetting, setNotAvailableSetting] = useState<
    EntitySetting[]
  >([]);
  const [commit] = useApiMutation(entitySettingPatch);
  const handleOpen = () => setDisplay(true);
  const handleClose = () => {
    setDisplay(false);
    setValue(false);
  };
  const retrieveNotAvailableSetting = (currentKey: keyof EntitySetting) => entitySettingsSelectedFiltered.filter(({ [currentKey]: v }) => v === null);
  const handleOpenFilesRef = () => {
    handleOpen();
    setTitle(t_i18n('Automatic references at file upload'));
    setDescription(
      t_i18n(
        'This configuration enables an entity to automatically construct an external reference from the uploaded file.',
      ),
    );
    setKey('platform_entity_files_ref');
    setNotAvailableSetting(
      retrieveNotAvailableSetting('platform_entity_files_ref'),
    );
  };
  const handleOpenHidden = () => {
    handleOpen();
    setTitle(t_i18n('Hidden in interface'));
    setDescription(
      t_i18n(
        'This configuration hides a specific entity type across the entire platform.',
      ),
    );
    setKey('platform_hidden_type');
    setNotAvailableSetting(retrieveNotAvailableSetting('platform_hidden_type'));
  };
  const handleOpenEnforceRef = () => {
    handleOpen();
    setTitle(t_i18n('Enforce references'));
    setDescription(
      t_i18n(
        'This configuration enables the requirement of a reference message on an entity creation or modification.',
      ),
    );
    setKey('enforce_reference');
    setNotAvailableSetting(retrieveNotAvailableSetting('enforce_reference'));
  };
  const handleAction = () => {
    const ids = entitySettingsSelectedFiltered
      .filter(
        (node) => !notAvailableSetting
          .map((n) => n.target_type)
          .includes(node.target_type),
      )
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
        style: { paddingLeft: navOpen ? 185 : 60, bottom: bannerHeightNumber },
      }}
    >
      <Toolbar style={{ minHeight: 54 }}>
        <Typography
          className={classes.title}
          color="inherit"
          variant="subtitle1"
        >
          <span className={classes.titleNumber}>
            {numberOfSelectedElements}
          </span>{' '}
          {t_i18n('selected')}{' '}
          <IconButton
            aria-label="clear"
            disabled={numberOfSelectedElements === 0}
            onClick={handleClearSelectedElements}
            size="small"
          >
            <ClearOutlined fontSize="small" />
          </IconButton>
        </Typography>
        <Tooltip title={t_i18n('Automatic references at file upload')}>
          <span>
            <IconButton
              aria-label="files-ref"
              disabled={
                numberOfSelectedElements === 0
                || numberOfSelectedElements
                === retrieveNotAvailableSetting('platform_entity_files_ref')
                  .length
              }
              onClick={handleOpenFilesRef}
              color="primary"
              size="small"
            >
              <FileOpenOutlined fontSize="small" />
            </IconButton>
          </span>
        </Tooltip>
        <Tooltip title={t_i18n('Hidden in interface')}>
          <span>
            <IconButton
              aria-label="hidden-entity"
              disabled={
                numberOfSelectedElements === 0
                || numberOfSelectedElements
                === retrieveNotAvailableSetting('platform_hidden_type').length
              }
              onClick={handleOpenHidden}
              color="primary"
              size="small"
            >
              <VisibilityOffOutlined fontSize="small" />
            </IconButton>
          </span>
        </Tooltip>
        <Tooltip title={t_i18n('Enforce references')}>
          <span>
            <IconButton
              aria-label="enforce-ref"
              disabled={
                numberOfSelectedElements === 0
                || numberOfSelectedElements
                === retrieveNotAvailableSetting('enforce_reference').length
              }
              onClick={handleOpenEnforceRef}
              color="primary"
              size="small"
            >
              <LocalOfferOutlined fontSize="small" />
            </IconButton>
          </span>
        </Tooltip>
      </Toolbar>
      <Dialog
        open={display}
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={true}
        onClose={handleClose}
      >
        <DialogTitle>{title}</DialogTitle>
        <DialogContent>
          <Alert severity="info" style={{ marginBottom: 20 }}>
            {description}
            {notAvailableSetting.length > 0 && (
              <div style={{ marginTop: 10 }}>
                <strong>
                  {t_i18n(
                    'Be careful, this setting is not available for the following selected entity types: ',
                  )}
                  <span>
                    {notAvailableSetting
                      .map((node) => t_i18n(`entity_${node.target_type}`))
                      .join(', ')}
                  </span>
                </strong>
              </div>
            )}
          </Alert>
          <FormGroup>
            <FormControlLabel
              control={
                <Switch checked={value} onChange={() => setValue(!value)} />
              }
              label={t_i18n('Enable this feature')}
            />
          </FormGroup>
        </DialogContent>
        <DialogActions>
          <Button variant="secondary" onClick={handleClose}>{t_i18n('Cancel')}</Button>
          <Button onClick={handleAction}>
            {t_i18n('Update')}
          </Button>
        </DialogActions>
      </Dialog>
    </Drawer>
  );
};

export default ToolBar;
