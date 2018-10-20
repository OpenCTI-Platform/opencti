import React, {Component} from 'react'
import {Route, Redirect} from 'react-router-dom'

class Root extends Component {
    render() {
        return (
            <Route exact path='/' render={() => (
                <Redirect to='/dashboard'/>
            )}/>
        )
    }
}

export default Root