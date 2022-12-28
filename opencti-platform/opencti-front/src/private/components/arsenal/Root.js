import React, { useContext } from 'react';
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

const Root = () => {
  const { helper } = useContext(UserContext);
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
        render={() => <Redirect to={`/dashboard/arsenal/${redirect}`} />}
      />
      <BoundaryRoute
        exact
        path="/dashboard/arsenal/malwares"
        component={Malwares}
      />
      <BoundaryRoute
        path="/dashboard/arsenal/malwares/:malwareId"
        component={RootMalware}
      />
      <BoundaryRoute
        exact
        path="/dashboard/arsenal/channels"
        component={Channels}
      />
      <BoundaryRoute
        path="/dashboard/arsenal/channels/:channelId"
        component={RootChannel}
      />
      <BoundaryRoute exact path="/dashboard/arsenal/tools" component={Tools} />
      <BoundaryRoute
        path="/dashboard/arsenal/tools/:toolId"
        component={RootTool}
      />
      <BoundaryRoute
        exact
        path="/dashboard/arsenal/vulnerabilities"
        component={Vulnerabilities}
      />
      <BoundaryRoute
        path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId"
        component={RootVulnerabilities}
      />
    </Switch>
  );
};

export default Root;
