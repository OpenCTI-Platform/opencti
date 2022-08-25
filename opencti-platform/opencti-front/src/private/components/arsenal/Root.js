import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Malwares from './Malwares';
import RootMalware from './malwares/Root';
import Channels from './Channels';
import RootChannel from './channels/Root';
import Narratives from './Narratives';
import RootNarrative from './narratives/Root';
import AttackPatterns from './AttackPatterns';
import RootAttackPattern from './attack_patterns/Root';
import RootCourseOfAction from './courses_of_action/Root';
import Tools from './Tools';
import RootTool from './tools/Root';
import Vulnerabilities from './Vulnerabilities';
import RootVulnerabilities from './vulnerabilities/Root';
import CoursesOfAction from './CoursesOfAction';
import { UserContext } from '../../../utils/Security';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <UserContext.Consumer>
        {({ helper }) => {
          let redirect = null;
          if (!helper.isEntityTypeHidden('Malware')) {
            redirect = 'malwares';
          } else if (!helper.isEntityTypeHidden('Attack-Pattern')) {
            redirect = 'attack_patterns';
          } else if (!helper.isEntityTypeHidden('Channel')) {
            redirect = 'channels';
          } else if (!helper.isEntityTypeHidden('Narrative')) {
            redirect = 'narratives';
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
                path="/dashboard/arsenal/narratives"
                component={Narratives}
              />
              <BoundaryRoute
                path="/dashboard/arsenal/narratives/:narrativeId"
                render={(routeProps) => (
                  <RootNarrative {...routeProps} me={me} />
                )}
              />
              <BoundaryRoute
                exact
                path="/dashboard/arsenal/attack_patterns"
                component={AttackPatterns}
              />
              <BoundaryRoute
                path="/dashboard/arsenal/attack_patterns/:attackPatternId"
                render={(routeProps) => (
                  <RootAttackPattern {...routeProps} me={me} />
                )}
              />
              <BoundaryRoute
                exact
                path="/dashboard/arsenal/courses_of_action"
                component={CoursesOfAction}
              />
              <BoundaryRoute
                path="/dashboard/arsenal/courses_of_action/:courseOfActionId"
                render={(routeProps) => (
                  <RootCourseOfAction {...routeProps} me={me} />
                )}
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
