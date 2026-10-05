/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { FilterMode } from '../../generated/graphql';
import { patchAttribute } from '../../database/middleware';
import { fullEntitiesList, storeLoadById } from '../../database/middleware-loader';
import { getEntitiesListFromCache, getEntitiesMapFromCache } from '../../database/cache';
import { publishCacheResetEvent } from '../../database/redis';
import { logApp } from '../../config/conf';
import { LockTimeoutError, TYPE_LOCK_ERROR } from '../../config/errors';
import { lockResources } from '../../lock/master-lock';
import { SOURCE_INTELLIGENCE_MANAGER_USER, SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { addDraftWorkspace } from '../draftWorkspace/draftWorkspace-domain';
import { type BasicStoreEntityDraftWorkspace, ENTITY_TYPE_DRAFT_WORKSPACE } from '../draftWorkspace/draftWorkspace-types';
import { DRAFT_STATUS_OPEN } from '../draftWorkspace/draftStatuses';
import { forwardDraftWork, openDraftForwarding, registerDraftClosureHandler } from '../draftWorkspace/draftWorkspace-closure';
import { userEditField } from '../user/user-domain';
import { type BasicStoreEntitySource, ENTITY_TYPE_SOURCE, SOURCE_KIND_CONNECTOR, SOURCE_KIND_INGESTION_FEED } from './sourceIntelligence-types';

type DraftContextUser = BasicStoreEntity & { draft_context?: string | null };

/**
 * A quarantine routes the data of a source into a review draft until an analyst lifts it. Closing (validating) or
 * deleting that draft must never release the source into the live knowledge: a new open draft takes over.
 */
const isOpenDraft = (draft: BasicStoreEntityDraftWorkspace | undefined): draft is BasicStoreEntityDraftWorkspace => {
  return draft !== undefined && draft.draft_status === DRAFT_STATUS_OPEN;
};

// Connector sources are quarantined through the draft context of their connector user
export const quarantinedConnectorUserId = (source: BasicStoreEntitySource) => {
  return source.source_kind === SOURCE_KIND_CONNECTOR ? (source.source_user_ids ?? [])[0] : undefined;
};

/**
 * Open quarantine draft of a quarantined source, created again when the previous one was closed or deleted.
 * Runs under a per-source lock and on the stored source (never the cache) so that concurrent callers share one draft.
 * Returns undefined when the source is not quarantined (anymore).
 */
export const renewQuarantineDraft = async (context: AuthContext, sourceId: string, closingDraftId?: string): Promise<string | undefined> => {
  let lock;
  try {
    lock = await lockResources([`source-quarantine-draft:${sourceId}`]);
    const source = await storeLoadById<BasicStoreEntitySource>(context, SYSTEM_USER, sourceId, ENTITY_TYPE_SOURCE);
    if (!source?.quarantined) {
      return undefined;
    }
    const current = source.quarantine_draft_id
      ? await storeLoadById<BasicStoreEntityDraftWorkspace>(context, SYSTEM_USER, source.quarantine_draft_id, ENTITY_TYPE_DRAFT_WORKSPACE)
      : undefined;
    // A draft being validated or deleted is still open in the store: it is replaced all the same
    let draftId = isOpenDraft(current) && current.internal_id !== closingDraftId ? current.internal_id : undefined;
    if (!draftId) {
      const draft = await addDraftWorkspace(context, SOURCE_INTELLIGENCE_MANAGER_USER, {
        name: `Quarantine - ${source.name}`,
        description: `Data routed by Source Intelligence while the source ${source.name} is quarantined (previous quarantine draft closed or deleted).`,
      });
      draftId = draft.id;
      await openDraftForwarding(draft.id);
      // Feed bundles already queued for the previous draft follow the quarantine into the new one
      if (source.quarantine_draft_id && draftId) {
        await forwardDraftWork(source.quarantine_draft_id, draftId);
      }
      await patchAttribute(context, SOURCE_INTELLIGENCE_MANAGER_USER, source.internal_id, ENTITY_TYPE_SOURCE, { quarantine_draft_id: draftId });
      await publishCacheResetEvent(ENTITY_TYPE_SOURCE);
      logApp.info('[OPENCTI-MODULE] Source intelligence quarantine draft renewed', { source_id: source.internal_id, previous_draft_id: source.quarantine_draft_id, draft_id: draftId });
    }
    const userId = quarantinedConnectorUserId(source);
    if (userId) {
      const connectorUser = await storeLoadById<DraftContextUser>(context, SYSTEM_USER, userId, ENTITY_TYPE_USER);
      if (connectorUser && connectorUser.draft_context !== draftId) {
        await userEditField(context, SOURCE_INTELLIGENCE_MANAGER_USER, userId, [{ key: 'draft_context', value: [draftId] }]);
      }
    }
    return draftId;
  } catch (err: any) {
    if (err?.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds: [sourceId] });
    }
    throw err;
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};

/**
 * Lifts the quarantine of a source under the lock of its quarantine draft, so the enforcement never restores it
 * half-way. The source is released first and its connector user leaves the draft last: a failure in between leaves
 * the connector writing into the draft, never into the live knowledge.
 */
export const releaseQuarantine = async (
  context: AuthContext,
  user: AuthUser,
  sourceId: string | undefined,
  connectorUser?: { userId: string; draftContext: string },
) => {
  let lock;
  try {
    if (sourceId) {
      lock = await lockResources([`source-quarantine-draft:${sourceId}`]);
      await patchAttribute(context, user, sourceId, ENTITY_TYPE_SOURCE, { quarantined: false, quarantine_draft_id: null });
      await publishCacheResetEvent(ENTITY_TYPE_SOURCE);
    }
    if (connectorUser) {
      await userEditField(context, user, connectorUser.userId, [{ key: 'draft_context', value: [connectorUser.draftContext] }]);
    }
  } catch (err: any) {
    if (err?.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds: [sourceId] });
    }
    throw err;
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};

/**
 * Draft receiving the next bundle of an ingestion feed: the open quarantine draft when the feed source is quarantined,
 * undefined otherwise. Never falls back to the live knowledge while the quarantine is in force.
 */
export const resolveFeedQuarantineDraftId = async (context: AuthContext, ingestionId: string): Promise<string | undefined> => {
  // Read from the store: a bundle routed from a cache not yet reset on this node would reach the live knowledge
  const filters = {
    mode: FilterMode.And,
    filters: [
      { key: ['source_kind'], values: [SOURCE_KIND_INGESTION_FEED] },
      { key: ['ref_id'], values: [ingestionId] },
      { key: ['quarantined'], values: ['true'] },
    ],
    filterGroups: [],
  };
  const [source] = await fullEntitiesList<BasicStoreEntitySource>(context, SYSTEM_USER, [ENTITY_TYPE_SOURCE], { filters, noFiltersChecking: true });
  if (!source) {
    return undefined;
  }
  const draft = source.quarantine_draft_id
    ? await storeLoadById<BasicStoreEntityDraftWorkspace>(context, SYSTEM_USER, source.quarantine_draft_id, ENTITY_TYPE_DRAFT_WORKSPACE)
    : undefined;
  if (isOpenDraft(draft)) {
    return draft.internal_id;
  }
  return renewQuarantineDraft(context, source.internal_id);
};

/**
 * Validating or deleting a quarantine draft renews it before the draft content is read or removed, so the
 * connector user of a quarantined source goes straight to the new draft and never writes in the live knowledge.
 */
export const renewQuarantinesOfClosingDraft = async (context: AuthContext, draftId: string) => {
  // A draft can be validated from inside it: the renewal always works in the live knowledge
  const liveContext: AuthContext = { ...context, draft_context: '' };
  // Read from the store: a cache not yet reset on this node must never let a quarantine lapse
  const filters = { mode: FilterMode.And, filters: [{ key: ['quarantined'], values: ['true'] }], filterGroups: [] };
  const sources = await fullEntitiesList<BasicStoreEntitySource>(liveContext, SYSTEM_USER, [ENTITY_TYPE_SOURCE], { filters, noFiltersChecking: true });
  const quarantined = sources.filter((source) => source.quarantine_draft_id === draftId);
  for (let i = 0; i < quarantined.length; i += 1) {
    await renewQuarantineDraft(liveContext, quarantined[i].internal_id, draftId);
  }
};

registerDraftClosureHandler(renewQuarantinesOfClosingDraft);

/**
 * Restores every quarantine whose draft was closed or deleted, or whose connector user left the draft context.
 * Called on each manager tick; reads the caches and only writes when something drifted.
 */
export const enforceQuarantines = async (context: AuthContext) => {
  const sources = await getEntitiesListFromCache<BasicStoreEntitySource>(context, SYSTEM_USER, ENTITY_TYPE_SOURCE);
  const quarantined = sources.filter((source) => source.quarantined === true);
  if (quarantined.length === 0) {
    return 0;
  }
  const drafts = await getEntitiesMapFromCache<BasicStoreEntityDraftWorkspace>(context, SYSTEM_USER, ENTITY_TYPE_DRAFT_WORKSPACE);
  const users = await getEntitiesMapFromCache<DraftContextUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  let renewed = 0;
  for (let i = 0; i < quarantined.length; i += 1) {
    const source = quarantined[i];
    const draft = source.quarantine_draft_id ? drafts.get(source.quarantine_draft_id) : undefined;
    const userId = quarantinedConnectorUserId(source);
    const userDrifted = userId !== undefined && users.get(userId)?.draft_context !== source.quarantine_draft_id;
    if (!isOpenDraft(draft) || userDrifted) {
      try {
        await renewQuarantineDraft(context, source.internal_id);
        renewed += 1;
      } catch (err) {
        logApp.error('[OPENCTI-MODULE] Source intelligence quarantine enforcement failed', { cause: err, source_id: source.internal_id });
      }
    }
  }
  return renewed;
};
