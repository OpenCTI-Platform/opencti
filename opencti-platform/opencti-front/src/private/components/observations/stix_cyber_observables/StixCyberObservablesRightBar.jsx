import React from 'react';
import PropTypes from 'prop-types';
import { assoc, compose, map, pipe, prop, sortBy, toLower } from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import List from '@mui/material/List';
import ListSubheader from '@mui/material/ListSubheader';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Checkbox from '@mui/material/Checkbox';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { FilterOffOutline } from 'mdi-material-ui';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { stixCyberObservablesLinesSubTypesQuery } from './StixCyberObservablesLines';
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

const StixCyberObservablesRightBar = ({
  types = [],
  handleToggle,
  handleClear,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const { bannerSettings } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();

  return (
    <Drawer
      variant="permanent"
      anchor="right"
      classes={{ paper: classes.drawerPaper }}
      PaperProps={{
        style: {
          paddingTop: bannerSettings.bannerHeight,
          paddingBottom: bannerSettings.bannerHeight,
        },
      }}
    >
      <div className={classes.toolbar} />
      <QueryRenderer
        query={stixCyberObservablesLinesSubTypesQuery}
        variables={{ type: 'Stix-Cyber-Observable' }}
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
              <List style={{ marginTop: settingsMessagesBannerHeight }}
                subheader={
                  <ListSubheader component="div">
                    {t('Observable types')}
                    <Tooltip title={t('Clear filters')}>
                      <IconButton
                        onClick={handleClear}
                        disabled={types.length === 0}
                        color="primary"
                        size="large"
                      >
                        <FilterOffOutline fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </ListSubheader>
                }
              >
                {translatedOrderedList.map((subType) => (
                  <ListItem
                    key={subType.id}
                    dense={true}
                    button={true}
                    onClick={() => handleToggle(subType.label)}
                    classes={{ root: classes.item }}
                  >
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

StixCyberObservablesRightBar.propTypes = {
  types: PropTypes.array,
  handleToggle: PropTypes.func,
  handleClear: PropTypes.func,
  openExports: PropTypes.bool,
};

export default StixCyberObservablesRightBar;
