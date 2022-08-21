import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { assoc, compose, map, pipe, prop, sortBy, toLower } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListSubheader from '@mui/material/ListSubheader';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Checkbox from '@mui/material/Checkbox';
import Drawer from '@mui/material/Drawer';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { FilterOffOutline } from 'mdi-material-ui';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { stixCyberObservablesLinesSubTypesQuery } from '../stix_cyber_observables/StixCyberObservablesLines';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 250,
    right: 0,
    padding: '0 0 20px 0',

    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  drawerPaperExports: {
    minHeight: '100vh',
    width: 250,
    right: 310,
    padding: '0 0 20px 0',

    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.easeOut,
      duration: theme.transitions.duration.leavingScreen,
    }),
  },
  listIcon: {
    marginRight: 0,
  },
  item: {
    padding: '0 0 0 6px',
  },
  itemField: {
    padding: '0 15px 0 15px',
  },
  toolbar: theme.mixins.toolbar,
});

class IndicatorsRightBar extends Component {
  render() {
    const {
      classes,
      t,
      indicatorTypes,
      observableTypes,
      handleToggleIndicatorType = [],
      handleToggleObservableType = [],
      handleClearObservableTypes,
      openExports,
    } = this.props;
    return (
      <Drawer
        variant="permanent"
        anchor="right"
        classes={{
          paper: openExports ? classes.drawerPaperExports : classes.drawerPaper,
        }}
      >
        <div className={classes.toolbar} />
        <List
          subheader={
            <ListSubheader component="div">{t('Indicator type')}</ListSubheader>
          }
        >
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleIndicatorType.bind(this, 'stix')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={indicatorTypes.includes('stix')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary="STIX" />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleIndicatorType.bind(this, 'pcre')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={indicatorTypes.includes('pcre')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary="PCRE" />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleIndicatorType.bind(this, 'sigma')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={indicatorTypes.includes('sigma')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary="SIGMA" />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleIndicatorType.bind(this, 'snort')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={indicatorTypes.includes('snort')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary="SNORT" />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleIndicatorType.bind(this, 'suricata')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={indicatorTypes.includes('suricata')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary="Suricata" />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleIndicatorType.bind(this, 'yara')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={indicatorTypes.includes('yara')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary="YARA" />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleIndicatorType.bind(this, 'tanium-signal')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={indicatorTypes.includes('tanium-signal')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary="Tanium Signal" />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleIndicatorType.bind(this, 'spl')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={indicatorTypes.includes('spl')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary="Splunk SPL" />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleIndicatorType.bind(this, 'eql')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={indicatorTypes.includes('eql')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary="Elastic EQL" />
          </ListItem>
        </List>
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
                <List
                  subheader={
                    <ListSubheader component="div">
                      {t('Observable type')}
                      <Tooltip title={t('Clear filters')}>
                        <IconButton
                          onClick={handleClearObservableTypes.bind(this)}
                          disabled={observableTypes.length === 0}
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
                      onClick={handleToggleObservableType.bind(
                        this,
                        subType.label,
                      )}
                      classes={{ root: classes.item }}
                    >
                      <Checkbox
                        checked={observableTypes.includes(subType.label)}
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
  }
}

IndicatorsRightBar.propTypes = {
  indicatorTypes: PropTypes.array,
  observableTypes: PropTypes.array,
  handleToggleIndicatorType: PropTypes.func,
  handleToggleObservableType: PropTypes.func,
  handleClearObservableTypes: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
  openExports: PropTypes.bool,
};

export default compose(inject18n, withStyles(styles))(IndicatorsRightBar);
