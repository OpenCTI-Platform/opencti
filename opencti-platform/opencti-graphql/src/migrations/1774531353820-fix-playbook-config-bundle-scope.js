import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { fullEntitiesList } from '../database/middleware-loader';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT } from '../modules/playbook/components/access-restrictions-component';
import { PLAYBOOK_CONTAINER_WRAPPER_COMPONENT } from '../modules/playbook/components/container-wrapper-component';
import { PLAYBOOK_CREATE_INDICATOR_COMPONENT } from '../modules/playbook/components/create-indicator-component';
import { PLAYBOOK_CREATE_OBSERVABLE_COMPONENT } from '../modules/playbook/components/create-observable-component';
import { PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT } from '../modules/playbook/components/manipulate-knowledge-component';
import { PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT } from '../modules/playbook/components/remove-access-restrictions-component';
import { PLAYBOOK_SECURITY_COVERAGE_COMPONENT } from '../modules/playbook/components/security-coverage-component';
import { PLAYBOOK_SHARING_COMPONENT } from '../modules/playbook/components/sharing-component';
import { PLAYBOOK_UNSHARING_COMPONENT } from '../modules/playbook/components/unsharing-component';
import { ENTITY_TYPE_PLAYBOOK, playbookBundleElementsToApply } from '../modules/playbook/playbook-types';
import { executionContext, SYSTEM_USER } from '../utils/access';

// Modification in playbook component configs.
// Before: boolean "all" to check if all elements of the bundle should be manipualted.
// Now: an enum "only-main", "all-elements" and "all-except-main"

const message = '[MIGRATION] Upgrade playbook configs with new attribute: applyToElements';

const IDS_TO_MANAGE = [
  PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.id,
  PLAYBOOK_CONTAINER_WRAPPER_COMPONENT.id,
  PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT.id,
  PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT.id,
  PLAYBOOK_SECURITY_COVERAGE_COMPONENT.id,
  PLAYBOOK_SHARING_COMPONENT.id,
  PLAYBOOK_UNSHARING_COMPONENT.id,
  PLAYBOOK_CREATE_INDICATOR_COMPONENT.id,
  PLAYBOOK_CREATE_OBSERVABLE_COMPONENT.id,
];

const elasticUpdate = (convertor) => {
  const playbooksUpdateQuery = {
    script: {
      params: { convertor },
      source: 'if (params.convertor.containsKey(ctx._source.internal_id)) { ctx._source.playbook_definition = params.convertor[ctx._source.internal_id]; }',
    },
    query: {
      term: {
        'entity_type.keyword': {
          value: ENTITY_TYPE_PLAYBOOK,
        },
      },
    },
  };
  return elUpdateByQueryForMigration(
    message,
    READ_INDEX_INTERNAL_OBJECTS,
    playbooksUpdateQuery,
  );
};

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration', SYSTEM_USER);

  // -- step 1: fetch the playbooks --
  const playbooks = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_PLAYBOOK]);

  // -- step 2: update the config of components --
  let playbooksDefinitionConvertor = {}; // contains new configs
  playbooks.forEach((playbook) => {
    const newDefinitionNodes = [];
    const playbookDefinition = JSON.parse(playbook.playbook_definition);

    playbookDefinition.nodes.forEach((node) => {
      // Component that need to be changed
      if (IDS_TO_MANAGE.includes(node.component_id)) {
        const nodeConfiguration = JSON.parse(node.configuration);
        if (nodeConfiguration.applyToElements === undefined) {
          const { all, excludeMainElement, ...configTokeep } = nodeConfiguration;
          // Set value for the new attribute
          let applyToElements = playbookBundleElementsToApply.onlyMain.value;
          if (all === true) {
            applyToElements = excludeMainElement
              ? playbookBundleElementsToApply.allExceptMain.value
              : playbookBundleElementsToApply.allElements.value;
          }
          // Construct the new config
          newDefinitionNodes.push({
            ...node,
            configuration: JSON.stringify({
              ...configTokeep,
              applyToElements,
            }),
          });
        } else {
          // No conversion needed if already new attribute
          newDefinitionNodes.push(node);
        }
      } else {
        // No conversion needed for other components
        newDefinitionNodes.push(node);
      }
    });

    // Add new config in the object used for elastic script
    playbooksDefinitionConvertor = {
      ...playbooksDefinitionConvertor,
      [playbook.internal_id]: JSON.stringify({
        ...playbookDefinition,
        nodes: newDefinitionNodes,
      }),
    };
  });

  // -- step 3: update the playbooks filters in elastic --
  await elasticUpdate(playbooksDefinitionConvertor);

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
