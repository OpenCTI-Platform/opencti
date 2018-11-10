import React, {Component} from 'react'
import {withRouter, Link} from 'react-router-dom'
import {injectIntl} from 'react-intl'
import {withStyles} from '@material-ui/core/styles'
import ClickAwayListener from '@material-ui/core/ClickAwayListener'
import MenuList from '@material-ui/core/MenuList'
import MenuItem from '@material-ui/core/MenuItem'
import ListItemIcon from '@material-ui/core/ListItemIcon'
import ListItemText from '@material-ui/core/ListItemText'
import Drawer from '@material-ui/core/Drawer'
import {Dashboard, Public, Domain, Assignment, BugReport, KeyboardArrowRight, KeyboardArrowLeft} from '@material-ui/icons'
import {Biohazard, AlarmLight, Application, Diamond, Cards, Fire} from 'mdi-material-ui'

const styles = theme => ({
  drawerPaper: {
    minHeight: '100vh',
    position: 'fixed',
    width: 60,
    overflow: 'hidden',
    backgroundColor: theme.palette.nav.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    })
  },
  drawerPaperOpen: {
    minHeight: '100vh',
    position: 'fixed',
    width: 220,
    overflow: 'hidden',
    backgroundColor: theme.palette.nav.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    })
  },
  menuList: {
    height: '100%',
  },
  listIcon: {
    marginRight: 5
  },
  listText: {
    paddingRight: 5
  },
  lastItem: {
    bottom: 0
  },
  logoContainer: {
    margin: '6px 20px 0px -5px'
  },
  logo: {
    cursor: 'pointer',
    width: 35
  },
  toolbar: theme.mixins.toolbar
})

class LeftBar extends Component {
  constructor(props) {
    super(props)
    this.state = {open: false}
  }

  toggle() {
    this.setState({open: !this.state.open})
  }

  handleClickAway() {
    if (this.state.open) {
      this.toggle()
    }
  }

  render() {
    const {intl, location, classes} = this.props
    return (
      <ClickAwayListener onClickAway={this.handleClickAway.bind(this)}>
        <Drawer
          variant='permanent'
          open={this.state.open}
          classes={{paper: this.state.open ? classes.drawerPaperOpen : classes.drawerPaper}}
        >
          <div className={classes.toolbar}/>
          <MenuList component='nav' classes={{root: classes.menuList}}>
            <MenuItem component={Link} to='/dashboard' onClick={this.handleClickAway.bind(this)} selected={location.pathname === '/dashboard'} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Dashboard/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={intl.formatMessage({id: 'Dashboard'})} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/actors' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/actors')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Public/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={intl.formatMessage({id: 'Actors'})} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/sectors' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/sectors')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Domain/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={intl.formatMessage({id: 'Sectors'})} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/intrusion_sets' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/intrusion_sets')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Diamond/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={intl.formatMessage({id: 'Intrusion sets'})} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/campaigns' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/campaigns')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <AlarmLight/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={intl.formatMessage({id: 'Campaigns'})} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/incidents' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/incidents')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Fire/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={intl.formatMessage({id: 'Incidents'})} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/malwares' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/malwares')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Biohazard/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={intl.formatMessage({id: 'Malwares'})} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/tools' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/tools')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Application/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={intl.formatMessage({id: 'Tools'})} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/vulnerabilities' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/vulnerabilities')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <BugReport/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={intl.formatMessage({id: 'Vulnerabilities'})} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/identities' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/identities')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Cards/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={intl.formatMessage({id: 'Identities'})} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/reports' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/reports')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Assignment/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={intl.formatMessage({id: 'Reports'})} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem onClick={this.toggle.bind(this)} dense={true} style={{position: 'absolute', bottom: 10, width: '100%'}}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                {this.state.open ? <KeyboardArrowLeft/> : <KeyboardArrowRight/>}
              </ListItemIcon>
            </MenuItem>
          </MenuList>
        </Drawer>
      </ClickAwayListener>
    )
  }
}

export default injectIntl(withRouter(withStyles(styles)(LeftBar)))