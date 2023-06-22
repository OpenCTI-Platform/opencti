import React from 'react';
import { Redirect, Switch } from 'react-router-dom';
import {
  SETTINGS,
  SETTINGS_SETACCESSES,
  SETTINGS_SETLABELS,
  SETTINGS_SETMARKINGS,
} from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';
import { BoundaryRoute } from '../Error';
import CaseTemplates from './case_templates/CaseTemplates';
import CaseTemplateTasks from './case_templates/CaseTemplateTasks';
import Groups from './Groups';
import RootGroup from './groups/Root';
import KillChainPhases from './KillChainPhases';
import Labels from './Labels';
import MarkingDefinitions from './MarkingDefinitions';
import Policies from './Policies';
import Retention from './Retention';
import Roles from './Roles';
import RootRole from './roles/Root';
import Rules from './Rules';
import Sessions from './Sessions';
import Settings from './Settings';
import StatusTemplates from './status_templates/StatusTemplates';
import RootSubType from './sub_types/Root';
import SubTypes from './sub_types/SubTypes';
import Users from './Users';
import RootUser from './users/Root';
import Vocabularies from './Vocabularies';
import VocabularyCategories from './VocabularyCategories';
import RootActivity from './activity/Root';
import SettingsOrganizations from "./SettingsOrganizations";
import RootSettingsOrganization from "./organizations/Root";

const Root = () => (
  <Switch>
    <Security needs={[SETTINGS]} placeholder={<Redirect to="/dashboard" />}>
      <BoundaryRoute exact path="/dashboard/settings" component={Settings} />
      <BoundaryRoute
        exact
        path="/dashboard/settings/accesses"
        render={() => (
          <Security
            needs={[SETTINGS_SETACCESSES]}
            placeholder={
              <BoundaryRoute
                exact
                path="/dashboard/settings/accesses"
                render={() => (
                  <Security
                    needs={[SETTINGS_SETMARKINGS]}
                    placeholder={<Redirect to="/dashboard/settings" />}
                  >
                    <Redirect to="/dashboard/settings/accesses/marking" />
                  </Security>
                )}
              />
            }
          >
            <Redirect to="/dashboard/settings/accesses/roles" />
          </Security>
        )}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/accesses/users"
        render={() => (
          <Security
            needs={[SETTINGS_SETACCESSES]}
            placeholder={<Redirect to={'/dashboard/settings'} />}
          >
            <Users />
          </Security>
        )}
      />
      <BoundaryRoute
        path="/dashboard/settings/accesses/users/:userId"
        render={() => (
          <Security
            needs={[SETTINGS_SETACCESSES]}
            placeholder={<Redirect to={'/dashboard/settings'} />}
          >
            <RootUser />
          </Security>
        )}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/accesses/organizations"
        render={() => (
          <Security
            needs={[SETTINGS_SETACCESSES]}
            placeholder={<Redirect to={'/dashboard/settings'} />}
          >
            <SettingsOrganizations />
          </Security>
        )}
      />
      {
        // TODO What is the difference between these two ways of doing? And why there is no capability check in one?
      }
      {/*<BoundaryRoute*/}
      {/*  path="/dashboard/settings/accesses/organizations/:organizationId"*/}
      {/*  component={RootSettingsOrganization}*/}
      {/*/>*/}
      <BoundaryRoute
        path="/dashboard/settings/accesses/organizations/:organizationId"
        render={() => (
          <Security
            needs={[SETTINGS_SETACCESSES]}
            placeholder={<Redirect to={'/dashboard/settings'} />}
          >
            <RootSettingsOrganization />
          </Security>
        )}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/accesses/roles"
        render={() => (
          <Security
            needs={[SETTINGS_SETACCESSES]}
            placeholder={<Redirect to={'/dashboard/settings'} />}
          >
            <Roles />
          </Security>
        )}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/accesses/policies"
        render={() => (
          <Security
            needs={[SETTINGS_SETACCESSES]}
            placeholder={<Redirect to={'/dashboard/policies'} />}
          >
            <Policies />
          </Security>
        )}
      />
      <BoundaryRoute
        path="/dashboard/settings/accesses/roles/:roleId"
        component={RootRole}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/accesses/groups"
        render={() => (
          <Security
            needs={[SETTINGS_SETACCESSES]}
            placeholder={<Redirect to={'/dashboard/settings'} />}
          >
            <Groups />
          </Security>
        )}
      />
      <BoundaryRoute
        path="/dashboard/settings/accesses/groups/:groupId"
        component={RootGroup}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/accesses/sessions"
        render={() => (
          <Security
            needs={[SETTINGS_SETACCESSES]}
            placeholder={<Redirect to={'/dashboard/settings'} />}
          >
            <Sessions />
          </Security>
        )}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/accesses/marking"
        render={() => (
          <Security
            needs={[SETTINGS_SETMARKINGS]}
            placeholder={<Redirect to={'/dashboard/settings'} />}
          >
            <MarkingDefinitions />
          </Security>
        )}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/activity"
        render={() => <Redirect to="/dashboard/settings/activity/audit" />}
      />
      <BoundaryRoute
        path="/dashboard/settings/activity"
        render={() => <RootActivity />}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/customization"
        render={() => (
          <Redirect to="/dashboard/settings/customization/entity_types" />
        )}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/customization/entity_types"
        component={SubTypes}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/customization/retention"
        component={Retention}
      />
      <BoundaryRoute
        path="/dashboard/settings/customization/entity_types/:subTypeId"
        render={() => <RootSubType />}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/vocabularies/status_templates"
        component={StatusTemplates}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/customization/rules"
        component={Rules}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/vocabularies"
        render={() => (
          <Security
            needs={[SETTINGS_SETLABELS]}
            placeholder={<Redirect to={'/dashboard/settings'} />}
          >
            <Redirect to="/dashboard/settings/vocabularies/labels" />
          </Security>
        )}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/vocabularies/labels"
        render={() => (
          <Security
            needs={[SETTINGS_SETLABELS]}
            placeholder={<Redirect to={'/dashboard/settings'} />}
          >
            <Labels />
          </Security>
        )}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/vocabularies/case_templates"
        render={() => (
          <Security
            needs={[SETTINGS_SETLABELS]}
            placeholder={<Redirect to={'/dashboard/settings'} />}
          >
            <CaseTemplates />
          </Security>
        )}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/vocabularies/case_templates/:caseTemplateId"
        render={() => (
          <Security needs={[SETTINGS_SETLABELS]} placeholder={<Redirect to={'/dashboard/settings'} />}>
            <CaseTemplateTasks />
          </Security>
        )}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/vocabularies/kill_chain_phases"
        render={() => (
          <Security
            needs={[SETTINGS_SETLABELS]}
            placeholder={<Redirect to={'/dashboard/settings'} />}
          >
            <KillChainPhases />
          </Security>
        )}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/vocabularies/fields"
        render={() => (
          <Security
            needs={[SETTINGS_SETLABELS]}
            placeholder={<Redirect to={'/dashboard/settings'} />}
          >
            <VocabularyCategories />
          </Security>
        )}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/vocabularies/fields/:category"
        render={() => (
          <Security
            needs={[SETTINGS_SETLABELS]}
            placeholder={<Redirect to={'/dashboard/settings'} />}
          >
            <Vocabularies />
          </Security>
        )}
      />
    </Security>
  </Switch>
);
export default Root;
