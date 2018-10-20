import React, {Component} from "react";
import graphql from "babel-plugin-relay/macro";
import Cookies from "universal-cookie";
import {Link, Route} from "react-router-dom";
import Home from "../private/components/Home";
import logo from "../resources/logo.svg";
import {Users} from "./components/user/Users";
import {withRouter} from 'react-router-dom'
import environment from "../relay/environment";
import {commitLocalUpdate, QueryRenderer} from 'react-relay';
import UserInformation from "./components/user/UserInformation";

const testQuery = graphql`
    query AppPrivateUserQuery {
        me {
            ...UserInformation_me
        }
    }
`;

class AppPrivate extends Component {

    callLogout() {
        //Call graphQL mutation logout to remove the token
        new Cookies().remove('opencti_token');
        this.props.history.push('/');
    }

    test() {
        commitLocalUpdate(environment, (store) => {
            let user = store.get('ebb7bbfa-fee4-4540-9993-5d98aca7fc02');
            user.setValue('test@est.com', 'email');
        });
    }

    render() {
        return (
            <div className="App">
                <QueryRenderer environment={environment} query={testQuery} variables={{}}
                    render={({error, props}) => {
                        if (error) {
                            return <div>Error! {error}</div>;
                        }
                        if (!props || !props.me) {
                            return <div>Loading...</div>;
                        }
                        return <div>
                            <header className="App-header">
                                <img src={logo} className="App-logo" alt="logo"/>
                                <p>PRIVATE ZONE</p>
                                <a className="App-link"
                                   href="https://reactjs.org"
                                   target="_blank"
                                   rel="noopener noreferrer">
                                    Learn React
                                </a>
                                <ul>
                                    <li>
                                        <Link to="/">Home</Link>
                                    </li>
                                    <li>
                                        <Link to="/private">Private</Link>
                                    </li>
                                    <li>
                                        <Link to="/private/users">Users</Link>
                                    </li>
                                </ul>
                            </header>
                            <div>
                                <div>Yop <UserInformation me={props.me}/>
                                    <button onClick={this.callLogout.bind(this)}>Logout</button>
                                    <button onClick={this.test.bind(this)}>Test</button>
                                </div>
                                <Route exact path="/private" component={Home} />
                                <Route exact path="/private/users" component={Users}/>
                            </div>
                        </div>
                    }}
                />
            </div>
        )
    }
}

export default withRouter(AppPrivate);