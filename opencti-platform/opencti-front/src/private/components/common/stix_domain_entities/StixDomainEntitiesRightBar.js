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
  toolbar: theme.mixins.toolbar,
});

class StixDomainEntitiesRightBar extends Component {
  render() {
    const {
      classes,
      t,
      stixDomainEntitiesTypes,
      handleToggleStixDomainEntityType,
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
            <ListSubheader component="div">{t('Entities types')}</ListSubheader>
          }
        >
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleStixDomainEntityType.bind(this, 'Sector')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={stixDomainEntitiesTypes.includes('Sector')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Sectors')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleStixDomainEntityType.bind(this, 'Region')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={stixDomainEntitiesTypes.includes('Region')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Regions')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleStixDomainEntityType.bind(this, 'Country')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={stixDomainEntitiesTypes.includes('Country')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Countries')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleStixDomainEntityType.bind(this, 'City')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={stixDomainEntitiesTypes.includes('City')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Cities')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleStixDomainEntityType.bind(
              this,
              'Organization',
            )}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={stixDomainEntitiesTypes.includes('Organization')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Organizations')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleStixDomainEntityType.bind(
              this,
              'Threat-Actor',
            )}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={stixDomainEntitiesTypes.includes('Threat-Actor')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Threat actors')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleStixDomainEntityType.bind(
              this,
              'Intrusion-Set',
            )}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={stixDomainEntitiesTypes.includes('Intrusion-Set')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Intrusion sets')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleStixDomainEntityType.bind(this, 'Campaign')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={stixDomainEntitiesTypes.includes('Campaign')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Campaigns')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleStixDomainEntityType.bind(this, 'Incident')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={stixDomainEntitiesTypes.includes('Incident')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Incidents')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleStixDomainEntityType.bind(this, 'Malware')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={stixDomainEntitiesTypes.includes('Malware')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Malwares')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleStixDomainEntityType.bind(this, 'Tool')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={stixDomainEntitiesTypes.includes('Tool')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Tools')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleStixDomainEntityType.bind(
              this,
              'Vulnerability',
            )}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={stixDomainEntitiesTypes.includes('Vulnerability')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Vulnerabilities')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleStixDomainEntityType.bind(
              this,
              'Attack-Pattern',
            )}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={stixDomainEntitiesTypes.includes('Attack-Pattern')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Attack patterns')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleStixDomainEntityType.bind(
              this,
              'Course-Of-Action',
            )}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={stixDomainEntitiesTypes.includes('Course-Of-Action')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Courses of action')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleStixDomainEntityType.bind(this, 'Indicator')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={stixDomainEntitiesTypes.includes('Indicator')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Indicators')} />
          </ListItem>
          <ListItem
            dense={true}
            button={true}
            onClick={handleToggleStixDomainEntityType.bind(this, 'Report')}
            classes={{ root: classes.item }}
          >
            <Checkbox
              checked={stixDomainEntitiesTypes.includes('Report')}
              disableRipple={true}
              size="small"
            />
            <ListItemText primary={t('Reports')} />
          </ListItem>
        </List>
      </Drawer>
    );
  }
}

StixDomainEntitiesRightBar.propTypes = {
  stixDomainEntitiesTypes: PropTypes.array,
  handleToggleStixDomainEntityType: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
  openExports: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntitiesRightBar);
