import React, {Component} from 'react'
import {withRouter, Link} from 'react-router-dom'
import {withStyles} from '@material-ui/core/styles'
import ClickAwayListener from '@material-ui/core/ClickAwayListener'
import MenuList from '@material-ui/core/MenuList'
import MenuItem from '@material-ui/core/MenuItem'
import ListItemIcon from '@material-ui/core/ListItemIcon'
import ListItemText from '@material-ui/core/ListItemText'
import Divider from '@material-ui/core/Divider'
import Drawer from '@material-ui/core/Drawer'
import {Dashboard, Public, Domain, Assignment, BugReport, KeyboardArrowRight, KeyboardArrowLeft} from '@material-ui/icons'
import {Biohazard, AlarmLight, Application, Diamond, BriefcaseDownload, Cards, Fire} from 'mdi-material-ui'
import {T} from '../../../components/I18n'

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
    const {location, classes} = this.props

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
              {this.state.open ? <ListItemText primary={<T>Dashboard</T>} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/actors' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/actors')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Public/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={<T>Actors</T>} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/sectors' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/sectors')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Domain/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={<T>Sectors</T>} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/threats' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/threats')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Diamond/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={<T>Threats</T>} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/campaigns' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/campaigns')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <AlarmLight/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={<T>Campaigns</T>} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/incidents' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/incidents')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Fire/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={<T>Incidents</T>} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/malwares' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/malwares')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Biohazard/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={<T>Malwares</T>} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <Divider/>
            <MenuItem component={Link} to='/dashboard/analysis' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/analysis')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Assignment/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={<T>Reports and analysis</T>} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/sources' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/sources')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <BriefcaseDownload/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={<T>External reports</T>} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/identities' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/identities')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Cards/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={<T>Identities</T>} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/tools' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/tools')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <Application/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={<T>Tools</T>} classes={{root: classes.listText}}/> : ""}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/vulnerabilities' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/vulnerabilities')} dense={true}>
              <ListItemIcon classes={{root: classes.listIcon}}>
                <BugReport/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={<T>Vulnerabilities</T>} classes={{root: classes.listText}}/> : ""}
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

export default withRouter(withStyles(styles)(LeftBar))