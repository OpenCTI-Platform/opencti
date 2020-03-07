import React, { Component } from 'react';
import PropTypes from 'prop-types';
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
    padding: '0 0 20px 0',
    position: 'fixed',
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

class StixObservablesRightBar extends Component {
  render() {
    const {
      classes, t, types = [], handleToggle, openExports,
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
            <ListSubheader component="div">
              {t('Observable types')}
            </ListSubheader>
          }
        >
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggle.bind(this, 'Autonomous-System')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={types.includes('Autonomous-System')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Autonomous systems')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggle.bind(this, 'Domain')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={types.includes('Domain')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Domain names')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggle.bind(this, 'Mac-Addr')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={types.includes('Mac-Addr')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('MAC addresses')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggle.bind(this, 'IPv4-Addr')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={types.includes('IPv4-Addr')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('IPv4 addresses')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggle.bind(this, 'IPv6-Addr')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={types.includes('IPv6-Addr')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('IPv6 addresses')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggle.bind(this, 'URL')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={types.includes('URL')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('URL')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggle.bind(this, 'Email')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={types.includes('Email')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Emails')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggle.bind(this, 'Mutex')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={types.includes('Mutex')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Mutex')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggle.bind(this, 'Directory')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={types.includes('Directory')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Directories')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggle.bind(this, 'File')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={types.includes('File')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Files')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggle.bind(this, 'Registry-Key')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={types.includes('Registry-Key')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Registry')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggle.bind(this, 'PDB-Path')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={types.includes('PDB-Path')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('PDB Path')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggle.bind(this, 'Windows-Service')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={types.includes('Windows-Service')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Windows services')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggle.bind(this, 'Windows-Scheduled-Task')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={types.includes('Windows-Scheduled-Task')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Windows scheduled tasks')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggle.bind(this, 'X509-Certificate')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={types.includes('X509-Certificate')}
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

StixObservablesRightBar.propTypes = {
  types: PropTypes.array,
  handleToggle: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
  openExports: PropTypes.bool,
};

export default compose(inject18n, withStyles(styles))(StixObservablesRightBar);
