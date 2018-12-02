import React, {Component} from 'react'
import {withStyles} from '@material-ui/core/styles'
import Paper from '@material-ui/core/Paper'
import Button from '@material-ui/core/Button'
import Typography from '@material-ui/core/Typography'
import {T} from '../../components/I18n'
import {i18nRegister} from '../../utils/Messages'
import {fetchUser, updateUser} from '../../actions/User'
import UserForm from './UserForm'
import PasswordForm from './user/PasswordForm'

const styles = (theme) => ({
    panel: {
        width: '50%',
        margin: '0 auto',
        marginBottom: 30,
        padding: '20px 20px 20px 20px',
        textAlign: 'left',
        backgroundColor: theme.palette.paper.background,
        color: theme.palette.text.main,
        borderRadius: 6
    },
    goIcon: {
        position: 'absolute',
        right: 10,
        marginRight: 0
    }
})

i18nRegister({
    fr: {
        'Profile': 'Profil',
        'Update': 'Modifier',
        'API access': 'Accès à l\'API',
        'API key': 'Clé d\'API',
        'Example': 'Exemple',
        'Password': 'Mot de passe'
    }
})

class Profile extends Component {
    componentDidMount() {
        this.props.fetchUser(this.props.userId)
    }

    onUpdate(data) {
        return this.props.updateUser(this.props.user.user_id, data)
    }

    onUpdatePassword(data) {
        return this.props.updateUser(this.props.user.user_id, {'user_plain_password': data.user_plain_password})
    }

    submitUser() {
        this.refs.userForm.getWrappedInstance().submit()
    }

    submitPassword() {
        this.refs.passwordForm.getWrappedInstance().submit()
    }

    render() {
        let initialValues = this.props.user !== undefined ? R.pick(['user_firstname', 'user_lastname', 'user_email', 'user_lang'], this.props.user) : undefined
        return (
            <div>
                <Paper classes={{root: this.props.classes.panel}} elevation={2}>

                    <UserForm form='user_update' ref='userForm' onSubmit={this.onUpdate.bind(this)} initialValues={initialValues}/>

                </Paper>
                <Paper classes={{root: this.props.classes.panel}} elevation={2}>
                    <Typography variant='h1' gutterBottom={true}>
                        <T>API access</T>
                    </Typography>
                    <div style={{marginTop: 20}}>
                        <Typography variant='h4' gutterBottom={true}>
                            <T>API key</T>
                        </Typography>
                        <pre>
                            {this.props.apiKey}
                            </pre>
                        <Typography variant='h4' gutterBottom={true}>
                            <T>Example</T>
                        </Typography>
                        <pre>
                            GET /api/intrusion_sets<br/>
                            Content-Type: application/json<br/>
                            X-Authorization-Token: {this.props.apiKey}
                        </pre>
                        <Button variant='raised' color='primary' component='a' href='/api/doc' style={{marginTop: 20}}>
                            <T>Documentation</T>
                        </Button>
                    </div>
                </Paper>
                <Paper classes={{root: this.props.classes.panel}} elevation={2}>
                    <Typography variant='h1' gutterBottom={true}>
                        <T>Password</T>
                    </Typography>
                    <PasswordForm form='password_update' ref='passwordForm' onSubmit={this.onUpdatePassword.bind(this)}/>
                    <Button variant='raised' color='primary' onClick={this.submitPassword.bind(this)} style={{marginTop: 30}}>
                        <T>Update</T>
                    </Button>
                </Paper>
            </div>
        )
    }
}

Profile.propTypes = {
    userId: PropTypes.string,
    apiKey: PropTypes.string,
    user: PropTypes.object,
    fetchUser: PropTypes.func,
    updateUser: PropTypes.func,
    classes: PropTypes.object.isRequired
}

const select = (state) => {
    let userId = R.path(['logged', 'user'], state.app)
    let apiKey = R.path(['logged', 'auth'], state.app)
    return {
        userId,
        apiKey,
        user: R.prop(userId, state.referential.entities.users)
    }
}

export default connect(select, {fetchUser, updateUser})(withStyles(styles)(Profile))