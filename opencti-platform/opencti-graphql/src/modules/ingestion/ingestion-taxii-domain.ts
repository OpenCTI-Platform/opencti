import { type BasicStoreEntityIngestionTaxii, ENTITY_TYPE_INGESTION_TAXII, type StoreEntityIngestionTaxii } from './ingestion-types';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { BUS_TOPICS } from '../../config/conf';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { AuthContext, AuthUser } from '../../types/user';
import { type EditInput, type IngestionTaxiiAddInput } from '../../generated/graphql';
import { addAuthenticationCredentials, removeAuthenticationCredentials, verifyIngestionAuthenticationContent } from './ingestion-common';
import { registerConnectorForIngestion, unregisterConnectorForIngestion } from '../../domain/connector';

export const findById = async (context: AuthContext, user: AuthUser, ingestionId: string, removeCredentials = false) => {
  const taxiiIngestion = await storeLoadById<BasicStoreEntityIngestionTaxii>(context, user, ingestionId, ENTITY_TYPE_INGESTION_TAXII);
  if (removeCredentials) {
    taxiiIngestion.authentication_value = removeAuthenticationCredentials(taxiiIngestion.authentication_type, taxiiIngestion.authentication_value) || '';
  }
  return taxiiIngestion;
};

export const findTaxiiIngestionPaginated = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return pageEntitiesConnection<BasicStoreEntityIngestionTaxii>(context, user, [ENTITY_TYPE_INGESTION_TAXII], opts);
};

export const findAllTaxiiIngestion = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return fullEntitiesList<BasicStoreEntityIngestionTaxii>(context, user, [ENTITY_TYPE_INGESTION_TAXII], opts);
};

export const addIngestion = async (context: AuthContext, user: AuthUser, input: IngestionTaxiiAddInput) => {
  if (input.authentication_value) {
    verifyIngestionAuthenticationContent(input.authentication_type, input.authentication_value);
  }
  const { element, isCreation } = await createEntity(context, user, input, ENTITY_TYPE_INGESTION_TAXII, { complete: true });
  if (isCreation) {
    await registerConnectorForIngestion(context, {
      id: element.id,
      type: 'TAXII',
      name: element.name,
      is_running: element.ingestion_running ?? false,
      connector_user_id: input.user_id,
    });
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates taxii ingestion \`${input.name}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_INGESTION_TAXII, input },
    });
  }
  return element;
};

export interface TaxiiIngestionPatch {
  current_state_cursor?: string | undefined;
  last_execution_date?: string;
  added_after_start?: string;
}

export const patchTaxiiIngestion = async (context: AuthContext, user: AuthUser, id: string, patch: TaxiiIngestionPatch) => {
  const verifiedPatch = patch;
  if (patch.current_state_cursor) {
    verifiedPatch.current_state_cursor = `${patch.current_state_cursor}`;
  }
  const patched = await patchAttribute<StoreEntityIngestionTaxii>(context, user, id, ENTITY_TYPE_INGESTION_TAXII, verifiedPatch);
  return patched.element;
};

export const ingestionEditField = async (context: AuthContext, user: AuthUser, ingestionId: string, input: EditInput[]) => {
  const patchInput = [...input];

  if (input.some((editInput) => editInput.key === 'authentication_value')) {
    const { authentication_value, authentication_type } = await findById(context, user, ingestionId);
    const authenticationValueField = input.find((editInput) => editInput.key === 'authentication_value');
    if (authenticationValueField?.value[0]) {
      verifyIngestionAuthenticationContent(authentication_type, authenticationValueField?.value[0]);
    }
    const updatedAuthenticationValue = addAuthenticationCredentials(
      authentication_value,
      authenticationValueField?.value[0],
      authentication_type,
    );

    const updatedInput = patchInput.map((editInput) => {
      if (editInput.key === 'authentication_value') {
        return {
          ...editInput,
          value: [updatedAuthenticationValue],
        };
      }
      return editInput;
    });

    patchInput.splice(0, patchInput.length, ...updatedInput);
  }

  // Reset `authentication_value` on `authentication_type` change
  if (input.some((editInput) => editInput.key === 'authentication_type')) {
    const resetAuthenticationValue: EditInput = {
      key: 'authentication_value',
      value: [''],
    };
    patchInput.push(resetAuthenticationValue);
  }

  if (input.some((editInput) => editInput.key === 'added_after_start')) {
    const cursorEditInput: EditInput = {
      key: 'current_state_cursor',
      value: [undefined],
    };
    patchInput.push(cursorEditInput);
  }

  const { element } = await updateAttribute<StoreEntityIngestionTaxii>(context, user, ingestionId, ENTITY_TYPE_INGESTION_TAXII, patchInput);
  await registerConnectorForIngestion(context, {
    id: element.id,
    type: 'TAXII',
    name: element.name,
    is_running: element.ingestion_running ?? false,
    connector_user_id: element.user_id,
  });

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for taxii ingestion \`${element.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_TAXII, input },
  });

  const notif = await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
  return {
    ...notif,
    authentication_value: removeAuthenticationCredentials(notif.authentication_type, notif.authentication_value),
  };
};

export const ingestionDelete = async (context: AuthContext, user: AuthUser, ingestionId: string) => {
  const deleted = await deleteElementById<StoreEntityIngestionTaxii>(context, user, ingestionId, ENTITY_TYPE_INGESTION_TAXII);
  await unregisterConnectorForIngestion(context, deleted.id);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes taxii ingestion \`${deleted.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_TAXII, input: deleted },
  });
  return ingestionId;
};

export const ingestionTaxiiResetState = async (context: AuthContext, user: AuthUser, ingestionId: string) => {
  await patchTaxiiIngestion(context, user, ingestionId, { current_state_cursor: undefined });
  const ingestionUpdated = await findById(context, user, ingestionId);

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `reset state of taxii ingestion \`${ingestionUpdated.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_TAXII, input: ingestionUpdated },
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, ingestionUpdated, user);
};
