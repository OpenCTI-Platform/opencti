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
import type { StixObject } from '../../types/stix-2-1-common';
import type { BasicStoreSettings } from '../../types/settings';
import { INVESTIGATION_MANAGER_USER, isUserCanAccessStixElement, isUserCanAccessStoreElement, isUserInPlatformOrganization, SYSTEM_USER } from '../../utils/access';
import { stixLoadById } from '../../database/middleware';
import { getEntityFromCache } from '../../database/cache';
import { storeNotificationEvent } from '../../database/stream/stream-handler';
import { extractStixRepresentative } from '../../database/stix-representative';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import { convertToNotificationUser, EVENT_NOTIFICATION_VERSION, getLiveNotifications, type KnowledgeNotificationEvent } from '../../manager/notificationManager';
import { logApp } from '../../config/conf';
import { InvestigationApprovalStatus, InvestigationRunStatus, TriggerEventType } from '../../generated/graphql';
import { type BasicStoreEntityInvestigationRun, SOURCE_INACCESSIBLE_CODE } from './investigationRun-types';

/** The run as it is served to a reader: findings withheld from them or not, live markings of its sources added. */
export type ServeInvestigationRun = (context: AuthContext, user: AuthUser, run: BasicStoreEntityInvestigationRun) => Promise<BasicStoreEntityInvestigationRun>;

export const INVESTIGATION_TRIGGER_AWAITING_APPROVAL = TriggerEventType.InvestigationAwaitingApproval;
export const INVESTIGATION_TRIGGER_COMPLETED = TriggerEventType.InvestigationCompleted;
export const INVESTIGATION_TRIGGER_FAILED = TriggerEventType.InvestigationFailed;

/** The trigger event a status change raises, if any: cancellations are the analyst's own act. */
export const investigationTriggerEventFor = (previous: string, next: string): TriggerEventType | null => {
  if (previous === next) return null;
  if (next === InvestigationRunStatus.AwaitingApproval) return INVESTIGATION_TRIGGER_AWAITING_APPROVAL;
  if (next === InvestigationRunStatus.Completed) return INVESTIGATION_TRIGGER_COMPLETED;
  if (next === InvestigationRunStatus.Failed) return INVESTIGATION_TRIGGER_FAILED;
  return null;
};

const pendingApprovalIds = (run: BasicStoreEntityInvestigationRun) => (run.approvals ?? [])
  .filter((approval) => approval.status === InvestigationApprovalStatus.Pending)
  .map((approval) => approval.id);

/**
 * The trigger event an update of a run raises, if any. A gate held while the
 * engine keeps investigating (an enrichment through a connector that requires
 * approval) waits for an analyst as much as a paused run does: the run stays
 * running so the engine can go on with its other sources, and the analysts
 * are told when the gate appears.
 */
export const investigationRunEventFor = (previous: BasicStoreEntityInvestigationRun, run: BasicStoreEntityInvestigationRun): TriggerEventType | null => {
  const statusEvent = investigationTriggerEventFor(previous.run_status, run.run_status);
  if (statusEvent || run.run_status !== InvestigationRunStatus.Running) return statusEvent;
  const before = new Set(pendingApprovalIds(previous));
  return pendingApprovalIds(run).some((id) => !before.has(id)) ? INVESTIGATION_TRIGGER_AWAITING_APPROVAL : null;
};

export const investigationNotificationMessage = (eventType: TriggerEventType, run: BasicStoreEntityInvestigationRun, representative: string, onCase: boolean) => {
  const target = `[${onCase ? 'case' : run.subject_type.toLowerCase()}] ${representative}`;
  switch (eventType) {
    case INVESTIGATION_TRIGGER_AWAITING_APPROVAL:
      return `Case Autopilot investigation of ${target} is waiting for an analyst approval`;
    case INVESTIGATION_TRIGGER_COMPLETED:
      return `Case Autopilot investigation of ${target} is completed`;
    default:
      return `Case Autopilot investigation of ${target} failed${run.status_reason ? `: ${run.status_reason}` : ''}`;
  }
};

/**
 * Deliver an investigation event to the live triggers listening to it (and to
 * the digests built on them). The notified object is the case of the run, or
 * its subject when the run has no case yet: every recipient must be able to
 * access it and match the trigger filters, exactly as for knowledge events.
 * The run is checked as it is served to each recipient, so the live access to
 * the sources it cites counts, not only the markings stored on it.
 */
export const notifyInvestigationRunStatus = async (
  context: AuthContext,
  previous: BasicStoreEntityInvestigationRun,
  run: BasicStoreEntityInvestigationRun,
  serve: ServeInvestigationRun,
) => {
  const eventType = investigationRunEventFor(previous, run);
  if (!eventType) return 0;
  try {
    const liveNotifications = await getLiveNotifications(context);
    const candidates = liveNotifications.filter(({ trigger }) => (trigger.event_types ?? []).includes(eventType));
    if (candidates.length === 0) return 0;
    // A case created in the run Draft is not live yet: the event is then delivered on the subject.
    const caseStix = run.case_id ? await stixLoadById(context, SYSTEM_USER, run.case_id) as StixObject | undefined : undefined;
    const stix = caseStix ?? await stixLoadById(context, SYSTEM_USER, run.subject_id) as StixObject | undefined;
    if (!stix) return 0;
    const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    const message = investigationNotificationMessage(eventType, run, extractStixRepresentative(stix), !!caseStix);
    let delivered = 0;
    for (let index = 0; index < candidates.length; index += 1) {
      const { users, trigger } = candidates[index];
      const filters = trigger.filters ? JSON.parse(trigger.filters) : trigger.raw_filters;
      const targets: KnowledgeNotificationEvent['targets'] = [];
      for (let userIndex = 0; userIndex < users.length; userIndex += 1) {
        const user: AuthUser = users[userIndex];
        const userContext = { ...context, user_inside_platform_organization: isUserInPlatformOrganization(user, settings) };
        // The run may carry stricter restrictions than its case, from what it cites: both must be readable.
        if (await isUserCanAccessStixElement(userContext, user, stix) && await isStixMatchFilterGroup(userContext, user, stix, filters)) {
          const view = await serve(userContext, user, run);
          if (view.end_reason_code !== SOURCE_INACCESSIBLE_CODE && await isUserCanAccessStoreElement(userContext, user, view)) {
            targets.push({ user: convertToNotificationUser(user, trigger.notifiers), type: eventType, message });
          }
        }
      }
      if (targets.length > 0) {
        const notificationEvent: KnowledgeNotificationEvent = {
          version: EVENT_NOTIFICATION_VERSION,
          notification_id: trigger.internal_id,
          type: 'live',
          targets,
          data: stix,
          streamMessage: message,
          origin: { user_id: INVESTIGATION_MANAGER_USER.id },
        };
        await storeNotificationEvent(context, notificationEvent);
        delivered += targets.length;
      }
    }
    return delivered;
  } catch (error) {
    // A notification never fails the run it reports on.
    logApp.error('[INVESTIGATION] Notification of an investigation run failed', { cause: error, runId: run.internal_id, eventType });
    return 0;
  }
};
