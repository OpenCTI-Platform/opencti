import React from 'react';
import { Redirect, Switch } from 'react-router-dom';
import Settings from './Settings';
import Users from './Users';
import RootUser from './users/Root';
import Groups from './Groups';
import Roles from './Roles';
import Sessions from './Sessions';
import MarkingDefinitions from './MarkingDefinitions';
import Rules from './Rules';
import KillChainPhases from './KillChainPhases';
import Labels from './Labels';
import Retention from './Retention';
import { BoundaryRoute } from '../Error';
import Security from '../../../utils/Security';
import {
  SETTINGS,
  SETTINGS_SETACCESSES, SETTINGS_SETLABELS,
  SETTINGS_SETMARKINGS,
} from '../../../utils/hooks/useGranted';
import StatusTemplates from './status_templates/StatusTemplates';
import Vocabularies from './Vocabularies';
import VocabularyCategories from './VocabularyCategories';
import SubTypes from './sub_types/SubTypes';
import RootSubType from './sub_types/Root';

const Root = () => (
    <Switch>
      <Security needs={[SETTINGS]} placeholder={<Redirect to="/dashboard" />}>
        <BoundaryRoute exact path="/dashboard/settings" component={Settings} />
        <BoundaryRoute
          exact
          path="/dashboard/settings/accesses"
          render={() => (
            <Security needs={[SETTINGS_SETMARKINGS]} placeholder={<Redirect to="/dashboard/settings/accesses/users" />}>
              <Redirect to="/dashboard/settings/accesses/marking" />
            </Security>
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/settings/accesses/users"
          render={() => (
            <Security needs={[SETTINGS_SETACCESSES]} placeholder={<Redirect to={'/dashboard/settings'} />}>
              <Users />
            </Security>
          )}
        />
        <BoundaryRoute
          path="/dashboard/settings/accesses/users/:userId"
          render={() => (
            <Security needs={[SETTINGS_SETACCESSES]} placeholder={<Redirect to={'/dashboard/settings'} />}>
              <RootUser />
            </Security>
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/settings/accesses/roles"
          render={() => (
            <Security needs={[SETTINGS_SETACCESSES]} placeholder={<Redirect to={'/dashboard/settings'} />}>
              <Roles />
            </Security>
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/settings/accesses/groups"
          render={() => (
            <Security needs={[SETTINGS_SETACCESSES]} placeholder={<Redirect to={'/dashboard/settings'} />}>
              <Groups />
            </Security>
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/settings/accesses/sessions"
          render={() => (
            <Security needs={[SETTINGS_SETACCESSES]} placeholder={<Redirect to={'/dashboard/settings'} />}>
              <Sessions />
            </Security>
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/settings/accesses/marking"
          render={() => (
            <Security needs={[SETTINGS_SETMARKINGS]} placeholder={<Redirect to={'/dashboard/settings'} />}>
              <MarkingDefinitions />
            </Security>
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/settings/entity_types"
          component={SubTypes}
        />
        <BoundaryRoute
          path="/dashboard/settings/entity_types/:subTypeId"
          render={() => <RootSubType />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/settings/vocabularies/statusTemplates"
          component={StatusTemplates}
        />
        <BoundaryRoute
          exact
          path="/dashboard/settings/retention"
          component={Retention}
        />
        <BoundaryRoute exact path="/dashboard/settings/rules" component={Rules} />
        <BoundaryRoute
          exact
          path="/dashboard/settings/vocabularies"
          render={() => (
            <Security needs={[SETTINGS_SETLABELS]} placeholder={<Redirect to={'/dashboard/settings'} />}>
              <Redirect to="/dashboard/settings/vocabularies/labels" />
            </Security>
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/settings/vocabularies/labels"
          render={() => (
            <Security needs={[SETTINGS_SETLABELS]} placeholder={<Redirect to={'/dashboard/settings'} />}>
              <Labels />
            </Security>
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/settings/vocabularies/kill_chain_phases"
          render={() => (
            <Security needs={[SETTINGS_SETLABELS]} placeholder={<Redirect to={'/dashboard/settings'} />}>
              <KillChainPhases />
            </Security>
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/settings/vocabularies/fields"
          render={() => (
            <Security needs={[SETTINGS_SETLABELS]} placeholder={<Redirect to={'/dashboard/settings'} />}>
              <VocabularyCategories />
            </Security>
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/settings/vocabularies/fields/:category"
          render={() => (
            <Security needs={[SETTINGS_SETLABELS]} placeholder={<Redirect to={'/dashboard/settings'} />}>
              <Vocabularies />
            </Security>
          )}
        />
      </Security>
    </Switch>
);
export default Root;
