import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Malwares from './Malwares';
import RootMalware from './malwares/Root';
import Channels from './Channels';
import RootChannel from './channels/Root';
import Tools from './Tools';
import RootTool from './tools/Root';
import Vulnerabilities from './Vulnerabilities';
import RootVulnerabilities from './vulnerabilities/Root';
import { UserContext } from '../../../utils/hooks/useAuth';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <UserContext.Consumer>
        {({ helper }) => {
          let redirect = null;
          if (!helper.isEntityTypeHidden('Malware')) {
            redirect = 'malwares';
          } else if (!helper.isEntityTypeHidden('Channel')) {
            redirect = 'channels';
          } else if (!helper.isEntityTypeHidden('Tool')) {
            redirect = 'tools';
          } else if (!helper.isEntityTypeHidden('Vulnerability')) {
            redirect = 'vulnerabilities';
          }
          return (
            <Switch>
              <BoundaryRoute
                exact
                path="/dashboard/arsenal"
                render={() => (
                  <Redirect to={`/dashboard/arsenal/${redirect}`} />
                )}
              />
              <BoundaryRoute
                exact
                path="/dashboard/arsenal/malwares"
                component={Malwares}
              />
              <BoundaryRoute
                path="/dashboard/arsenal/malwares/:malwareId"
                render={(routeProps) => <RootMalware {...routeProps} me={me} />}
              />
              <BoundaryRoute
                exact
                path="/dashboard/arsenal/channels"
                component={Channels}
              />
              <BoundaryRoute
                path="/dashboard/arsenal/channels/:channelId"
                render={(routeProps) => <RootChannel {...routeProps} me={me} />}
              />
              <BoundaryRoute
                exact
                path="/dashboard/arsenal/tools"
                component={Tools}
              />
              <BoundaryRoute
                path="/dashboard/arsenal/tools/:toolId"
                render={(routeProps) => <RootTool {...routeProps} me={me} />}
              />
              <BoundaryRoute
                exact
                path="/dashboard/arsenal/vulnerabilities"
                component={Vulnerabilities}
              />
              <BoundaryRoute
                path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId"
                render={(routeProps) => (
                  <RootVulnerabilities {...routeProps} me={me} />
                )}
              />
            </Switch>
          );
        }}
      </UserContext.Consumer>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
