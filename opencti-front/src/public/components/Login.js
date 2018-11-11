import React, {Component} from 'react'
import ReactDocumentTitle from 'react-document-title'
import {withStyles} from '@material-ui/core/styles'
import Button from '@material-ui/core/Button'
import {Google, FacebookBox, GithubCircle} from 'mdi-material-ui'
import {StandaloneIntlProvider} from '../../components/AppIntlProvider'
import logo from '../../resources/images/logo_opencti.png'

const loginHeight = 400

const styles = theme => ({
  container: {
    textAlign: 'center',
    margin: '0 auto',
    width: 400,
    height: loginHeight,
  },
  login: {
    paddingBottom: '15px'
  },
  logo: {
    width: '250px',
    margin: '0px 0px 20px 0px',
  },
  buttonGoogle: {
    margin: theme.spacing.unit,
    color: '#ffffff',
    backgroundColor: '#f44336',
    '&:hover': {
      backgroundColor: '#bd332e'
    }
  },
  buttonFacebook: {
    margin: theme.spacing.unit,
    color: '#ffffff',
    backgroundColor: '#4267b2',
    '&:hover': {
      backgroundColor: '#374a88'
    }
  },
  buttonGithub: {
    margin: theme.spacing.unit,
    color: '#ffffff',
    backgroundColor: '#222222',
    '&:hover': {
      backgroundColor: '#121212'
    }
  },
  iconSmall: {
    marginRight: theme.spacing.unit,
    fontSize: 20
  }
})

class Login extends Component {
  constructor(props) {
    super(props)
    this.state = {width: 0, height: 0}
    this.updateWindowDimensions = this.updateWindowDimensions.bind(this)
  }

  componentDidMount() {
    this.updateWindowDimensions()
    window.addEventListener('resize', this.updateWindowDimensions)
  }

  componentWillUnmount() {
    window.removeEventListener('resize', this.updateWindowDimensions)
  }

  updateWindowDimensions() {
    this.setState({width: window.innerWidth, height: window.innerHeight})
  }

  render() {
    const marginTop = (this.state.height / 2) - (loginHeight / 2) - 50
    return (
      <StandaloneIntlProvider>
        <ReactDocumentTitle title='OpenCTI platform - Dashboard login'>
          <div className={this.props.classes.container} style={{marginTop: marginTop}}>
            <img src={logo} alt='logo' className={this.props.classes.logo}/>
            <div className={this.props.classes.login}>
              Login form
            </div>
            <Button className={this.props.classes.buttonGoogle} variant='contained' size='small' component='a' href='/auth/google'>
              <Google className={this.props.classes.iconSmall}/>
              Google
            </Button>
            <Button className={this.props.classes.buttonFacebook} variant='contained' size='small' component='a' href='/auth/facebook'>
              <FacebookBox className={this.props.classes.iconSmall}/>
              Facebook
            </Button>
            <Button className={this.props.classes.buttonGithub} variant='contained' size='small' component='a' href='/auth/github'>
              <GithubCircle className={this.props.classes.iconSmall}/>
              Github
            </Button>
          </div>
        </ReactDocumentTitle>
      </StandaloneIntlProvider>
    )
  }
}

export default withStyles(styles)(Login)