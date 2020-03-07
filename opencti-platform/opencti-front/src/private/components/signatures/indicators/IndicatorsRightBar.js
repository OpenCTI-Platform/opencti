import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListSubheader from '@material-ui/core/ListSubheader';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import Checkbox from '@material-ui/core/Checkbox';
import Drawer from '@material-ui/core/Drawer';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 250,
    right: 0,
    padding: '0 0 20px 0',
    backgroundColor: theme.palette.navAlt.background,
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
    backgroundColor: theme.palette.navAlt.background,
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
        </List>
        <List
          subheader={
            <ListSubheader component="div">
              {t('Main observable type')}
            </ListSubheader>
          }
        >
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleObservableType.bind(this, 'Autonomous-System')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={observableTypes.includes('Autonomous-System')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Autonomous systems')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleObservableType.bind(this, 'Domain')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={observableTypes.includes('Domain')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Domain names')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleObservableType.bind(this, 'Mac-Addr')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={observableTypes.includes('Mac-Addr')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('MAC addresses')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleObservableType.bind(this, 'IPv4-Addr')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={observableTypes.includes('IPv4-Addr')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('IPv4 addresses')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleObservableType.bind(this, 'IPv6-Addr')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={observableTypes.includes('IPv6-Addr')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('IPv6 addresses')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleObservableType.bind(this, 'URL')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={observableTypes.includes('URL')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('URL')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleObservableType.bind(this, 'Email*')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={observableTypes.includes('Email*')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Emails')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleObservableType.bind(this, 'Mutex')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={observableTypes.includes('Mutex')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Mutex')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleObservableType.bind(this, 'Directory')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={observableTypes.includes('Directory')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Directories')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleObservableType.bind(this, 'File*')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={observableTypes.includes('File*')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Files')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleObservableType.bind(this, 'Registry-Key*')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={observableTypes.includes('Registry-Key*')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Registry')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleObservableType.bind(this, 'PDB-Path')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={observableTypes.includes('PDB-Path')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('PDB Path')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleObservableType.bind(this, 'Windows-Service')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={observableTypes.includes('Windows-Service')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Windows services')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleObservableType.bind(
              this,
              'Windows-Scheduled-Task',
            )}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={observableTypes.includes('Windows-Scheduled-Task')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Windows scheduled tasks')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleObservableType.bind(this, 'X509-Certificate')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={observableTypes.includes('X509-Certificate')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('X509 Certificates')} />
          </ListItem>
        </List>
      </Drawer>
    );
  }
}

IndicatorsRightBar.propTypes = {
  indicatorTypes: PropTypes.array,
  observableTypes: PropTypes.array,
  handleToggleIndicatorType: PropTypes.func,
  handleToggleObservableType: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
  openExports: PropTypes.bool,
};

export default compose(inject18n, withStyles(styles))(IndicatorsRightBar);
