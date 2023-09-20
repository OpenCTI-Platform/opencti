import React from 'react';
import PropTypes from 'prop-types';
import { compose, pipe, sortBy, prop, toLower, map, assoc } from 'ramda';
import List from '@mui/material/List';
import makeStyles from '@mui/styles/makeStyles';
import ListSubheader from '@mui/material/ListSubheader';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Checkbox from '@mui/material/Checkbox';
import Drawer from '@mui/material/Drawer';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { FilterOffOutline } from 'mdi-material-ui';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { stixDomainObjectsLinesSubTypesQuery } from './StixDomainObjectsLines';
import useAuth from '../../../../utils/hooks/useAuth';
import { useSettingsMessagesBannerHeight } from '../../settings/settings_messages/SettingsMessagesBanner';

const useStyles = makeStyles((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 250,
    padding: '0 0 20px 0',
    position: 'fixed',
    zIndex: 1100,
  },
  item: {
    padding: '0 0 0 6px',
  },
  toolbar: theme.mixins.toolbar,
}));

const StixDomainObjectsRightBar = ({ types = [], handleToggle, handleClear }) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const { bannerSettings } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();

  return (
      <Drawer variant="permanent"
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
      >
        <div className={classes.toolbar} />
        <QueryRenderer
          query={stixDomainObjectsLinesSubTypesQuery}
          variables={{ type: 'Stix-Domain-Object' }}
          render={({ props }) => {
            if (props && props.subTypes) {
              const subTypesEdges = props.subTypes.edges;
              const sortByLabel = sortBy(compose(toLower, prop('tlabel')));
              const translatedOrderedList = pipe(
                map((n) => n.node),
                map((n) => assoc('tlabel', t(`entity_${n.label}`), n)),
                sortByLabel,
              )(subTypesEdges);
              return (
                <List style={{ marginTop: bannerSettings.bannerHeightNumber + settingsMessagesBannerHeight }}
                  sx={{ marginBottom: bannerSettings.bannerHeight }}
                  subheader={
                    <ListSubheader component="div">
                      {t('Entity types')}
                      <Tooltip title={t('Clear filters')}>
                        <span>
                          <IconButton onClick={handleClear}
                            disabled={types.length === 0}
                            color="primary"
                            size="large">
                            <FilterOffOutline fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    </ListSubheader>
                  }
                >
                  {translatedOrderedList.map((subType) => (
                    <ListItem key={subType.id}
                      dense={true}
                      button={true}
                      onClick={() => handleToggle(subType.label)}
                      classes={{ root: classes.item }}>
                      <Checkbox
                        checked={types.includes(subType.label)}
                        disableRipple={true}
                        size="small"
                      />
                      <ListItemText primary={subType.tlabel} />
                    </ListItem>
                  ))}
                </List>
              );
            }
            return <div />;
          }}
        />
      </Drawer>
  );
};

StixDomainObjectsRightBar.propTypes = {
  types: PropTypes.array,
  handleToggle: PropTypes.func,
  handleClear: PropTypes.func,
  openExports: PropTypes.bool,
};

export default StixDomainObjectsRightBar;
