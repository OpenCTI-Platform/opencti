import { type BasicStoreEntityIngestionRss, ENTITY_TYPE_INGESTION_RSS, type StoreEntityIngestionRss } from './ingestion-types';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import {
  fullEntitiesList,
  pageEntitiesConnection,
  storeLoadById,
  storeLoadByIds
} from '../../database/middleware-loader';
import {BUS_TOPICS, PLATFORM_VERSION} from '../../config/conf';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { AuthContext, AuthUser } from '../../types/user';
import type {EditInput, IngestionRssAddAutoUserInput, IngestionRssAddInput} from '../../generated/graphql';
import { registerConnectorForIngestion, unregisterConnectorForIngestion } from '../../domain/connector';
import {createOnTheFlyUser} from "../user/user-domain";
import type {FileHandle} from "fs/promises";
import {extractContentFrom} from "../../utils/fileToContent";
import {isCompatibleVersionWithMinimal} from "../../utils/version";
import {FunctionalError} from "../../config/errors";
import type {BasicStoreEntityMarkingDefinition} from "../../types/store";
import {ENTITY_TYPE_MARKING_DEFINITION} from "../../schema/stixMetaObject";

const MINIMAL_RSS_FEED_COMPATIBLE_VERSION = '7.260309.0';

export const findById = (context: AuthContext, user: AuthUser, ingestionId: string) => {
  return storeLoadById<BasicStoreEntityIngestionRss>(context, user, ingestionId, ENTITY_TYPE_INGESTION_RSS);
};

export const findRssIngestionPaginated = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return pageEntitiesConnection<BasicStoreEntityIngestionRss>(context, user, [ENTITY_TYPE_INGESTION_RSS], opts);
};

export const findAllRssIngestion = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return fullEntitiesList<BasicStoreEntityIngestionRss>(context, user, [ENTITY_TYPE_INGESTION_RSS], opts);
};

export const addIngestion = async (context: AuthContext, user: AuthUser, input: IngestionRssAddInput) => {
  let onTheFlyCreatedUser;
  let finalInput;
  if (input.automatic_user) {
    onTheFlyCreatedUser = await createOnTheFlyUser(context, user, { userName: input.user_id, confidenceLevel: input.confidence_level, serviceAccount: true });
    finalInput = {
      ...((({ automatic_user: _, confidence_level: __, ...inputWithoutAutomaticFields }) => inputWithoutAutomaticFields)(input)),
      user_id: onTheFlyCreatedUser.id,
    };
  } else {
    finalInput = {
      ...((({ automatic_user: _, confidence_level: __, ...inputWithoutAutomaticFields }) => inputWithoutAutomaticFields)(input)),
    };
  }

  const { element, isCreation } = await createEntity(context, user, finalInput, ENTITY_TYPE_INGESTION_RSS, { complete: true });

  if (isCreation) {
    await registerConnectorForIngestion(context, {
      id: element.id,
      type: 'RSS',
      name: element.name,
      is_running: element.ingestion_running ?? false,
      connector_user_id: input.user_id,
    });
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates rss ingestion \`${input.name}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_INGESTION_RSS, input },
    });
  }
  return element;
};

export const patchRssIngestion = async (context: AuthContext, user: AuthUser, id: string, patch: object) => {
  const patched = await patchAttribute(context, user, id, ENTITY_TYPE_INGESTION_RSS, patch);
  return patched.element;
};
export const ingestionAddAutoUser = async (context: AuthContext, user: AuthUser, ingestionRssId: string, input: IngestionRssAddAutoUserInput) => {
  const onTheFlyCreatedUser = await createOnTheFlyUser(context, user,
    { userName: input.user_name, confidenceLevel: input.confidence_level, serviceAccount: true });

  return ingestionEditField(context, user, ingestionRssId, [{ key: 'user_id', value: [onTheFlyCreatedUser.id] }]);
};

export const ingestionEditField = async (context: AuthContext, user: AuthUser, ingestionId: string, input: EditInput[]) => {
  const { element } = await updateAttribute<StoreEntityIngestionRss>(context, user, ingestionId, ENTITY_TYPE_INGESTION_RSS, input);
  await registerConnectorForIngestion(context, {
    id: element.id,
    type: 'RSS',
    name: element.name,
    is_running: element.ingestion_running ?? false,
    connector_user_id: element.user_id,
  });
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for rss ingestion \`${element.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_RSS, input },
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};

export const ingestionDelete = async (context: AuthContext, user: AuthUser, ingestionId: string) => {
  const deleted = await deleteElementById<StoreEntityIngestionRss>(context, user, ingestionId, ENTITY_TYPE_INGESTION_RSS);
  await unregisterConnectorForIngestion(context, deleted.id);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes rss ingestion \`${deleted.name}\``,
    context_data: { id: ingestionId, entity_type: ENTITY_TYPE_INGESTION_RSS, input: deleted },
  });
  return ingestionId;
};

export const rssFeedAddInputFromImport = async (file: Promise<FileHandle>) => {
  const parsedData = await extractContentFrom(file);

  // check platform version compatibility
  if (!isCompatibleVersionWithMinimal(parsedData.openCTI_version, MINIMAL_RSS_FEED_COMPATIBLE_VERSION)) {
    throw FunctionalError(
      `Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: ${MINIMAL_RSS_FEED_COMPATIBLE_VERSION}`,
      { reason: parsedData.openCTI_version },
    );
  }

  return parsedData.configuration;
}

export const rssFeedExport = async ( context: AuthContext,
                                     user: AuthUser,ingestionRss: BasicStoreEntityIngestionRss) => {
  const {
    name,
    description,
    scheduling_period,
    uri,
    current_state_date,
    report_types,
    object_marking_refs
  } = ingestionRss;
  const basicMarkingDefinitions = await storeLoadByIds<BasicStoreEntityMarkingDefinition>(context, user, object_marking_refs ?? [], ENTITY_TYPE_MARKING_DEFINITION)
  const markingDefinitionsFormated = basicMarkingDefinitions.map((marking) => {
    return {label: marking.definition, value: marking.internal_id}
  })
  return JSON.stringify({
    openCTI_version: PLATFORM_VERSION,
    type: 'rssFeeds',
    configuration: {
      name,
      description,
      scheduling_period,
      uri,
      current_state_date,
      report_types,
      object_marking_refs: markingDefinitionsFormated
    },
  });
};