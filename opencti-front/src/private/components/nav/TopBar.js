import React, { Component } from 'react'
import { withRouter, Link } from 'react-router-dom'
import graphql from 'babel-plugin-relay/macro'
import Cookies from 'universal-cookie'
import { QueryRenderer } from 'react-relay'
import * as R from 'ramda'
import { withStyles } from '@material-ui/core/styles'
import AppBar from '@material-ui/core/AppBar'
import Toolbar from '@material-ui/core/Toolbar'
import Typography from '@material-ui/core/Typography'
import IconButton from '@material-ui/core/IconButton'
import { AccountCircle } from '@material-ui/icons'
import Menu from '@material-ui/core/Menu'
import MenuItem from '@material-ui/core/MenuItem'
import environment from '../../../relay/environment'
import { T } from '../../../components/I18n'
import logo from '../../../resources/images/logo.png'
import UserInformation from "../user/UserInformation";

const styles = theme => ({
  appBar: {
    zIndex: theme.zIndex.drawer + 1,
    backgroundColor: theme.palette.header.background,
    color: theme.palette.header.text
  },
  flex: {
    flexGrow: 1
  },
  logoButton: {
    marginLeft: -23,
    marginRight: 20,
  },
  logo: {
    cursor: 'pointer',
    width: 35,
    height: 35
  },
  progressBar: {
    height: 2
  }
})

const testQuery = graphql`
    query TopBarUserQuery {
        me {
            ...UserInformation_me
        }
    }
`

class TopBar extends Component {
  constructor(props) {
    super(props)
    this.state = {menuOpen: false}
  }

  handleOpenMenu(event) {
    event.preventDefault()
    this.setState({menuOpen: true, anchorEl: event.currentTarget})
  }

  handleCloseMenu() {
    this.setState({menuOpen: false})
  }

  handleLogout() {
    this.handleCloseMenu()
    new Cookies().remove('opencti_token')
    this.props.history.push('/')
  }

  render() {
    const {classes} = this.props

    return (
      <AppBar position='fixed' className={classes.appBar}>
        <QueryRenderer environment={environment} query={testQuery} variables={{}} render={({error, props}) => {
          return (
            <Toolbar>
              <IconButton classes={{root: classes.logoButton}} color='inherit' aria-label='Menu' component={Link}
                          to='/dashboard'>
                <img src={logo} alt='logo' className={classes.logo}/>
              </IconButton>
              <Typography variant='h6' color='inherit' className={classes.flex}>
                OpenCTI - Cyber threat intelligence platform
              </Typography>
              <div>
                <IconButton
                  size='large'
                  aria-owns={this.state.open ? 'menu-appbar' : null}
                  aria-haspopup='true'
                  onClick={this.handleOpenMenu.bind(this)}
                  color='inherit'>
                  <span>{props && props.me ? props.me.email : ''}</span>
                  <AccountCircle color='inherit' style={{fontSize: 35}}/>
                  {props && props.me ?
                    <Typography variant='h6' color='inherit' className={classes.flex}>
                      <UserInformation me={props.me}/>
                    </Typography> : ''}
                </IconButton>
                <Menu
                  id='menu-appbar'
                  style={{marginTop: 40, zIndex: 2100}}
                  anchorEl={this.state.anchorEl}
                  open={this.state.menuOpen}
                  onClose={this.handleCloseMenu.bind(this)}>
                  <MenuItem component={Link} to='/dashboard/profile'
                            onClick={this.handleCloseMenu.bind(this)}><T>Profile</T></MenuItem>
                  {R.pathOr(false, ['me', 'admin'], props) ? <MenuItem component={Link} to='/admin'
                                                                       onClick={this.adminClick.bind(this)}><T>Admin</T></MenuItem> : ''}
                  <MenuItem onClick={this.handleLogout.bind(this)}><T>Logout</T></MenuItem>
                </Menu>
              </div>
            </Toolbar>
          )
        }}
        />
      </AppBar>
    )
  }
}

export default withRouter(withStyles(styles)(TopBar))