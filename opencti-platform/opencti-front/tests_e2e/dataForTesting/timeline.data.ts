import { APIRequestContext } from '@playwright/test';
import { graphqlQuery } from './query-utils';

const mutate = async <T>(request: APIRequestContext, query: string, field: string): Promise<T> => {
  const response = await graphqlQuery(request, query);
  const json = await response.json();
  if (json.errors?.length) {
    throw new Error(`${field} failed: ${JSON.stringify(json.errors)}`);
  }
  return json.data[field] as T;
};

export interface TimelineCase {
  caseId: string;
  malwareId: string;
  taskId: string;
}

/**
 * An incident response holding a malware seen over three days and a task due two days after the opening,
 * with its timeline derived once.
 */
export const addTimelineCase = async (request: APIRequestContext, name: string, taskName: string): Promise<TimelineCase> => {
  const malware = await mutate<{ id: string }>(request, `
    mutation {
      malwareAdd(input: {
        name: ${JSON.stringify(`${name} malware`)},
        first_seen: "2026-02-01T09:00:00.000Z",
        last_seen: "2026-02-04T09:00:00.000Z"
      }) { id }
    }
  `, 'malwareAdd');
  const caseIncident = await mutate<{ id: string }>(request, `
    mutation {
      caseIncidentAdd(input: {
        name: ${JSON.stringify(name)},
        created: "2026-02-04T12:00:00.000Z",
        objects: [${JSON.stringify(malware.id)}]
      }) { id }
    }
  `, 'caseIncidentAdd');
  const task = await mutate<{ id: string }>(request, `
    mutation {
      taskAdd(input: {
        name: ${JSON.stringify(taskName)},
        created: "2026-02-04T13:00:00.000Z",
        due_date: "2026-02-06T13:00:00.000Z",
        objects: [${JSON.stringify(caseIncident.id)}]
      }) { id }
    }
  `, 'taskAdd');
  await regenerateTimeline(request, caseIncident.id);
  return { caseId: caseIncident.id, malwareId: malware.id, taskId: task.id };
};

export const regenerateTimeline = async (request: APIRequestContext, containerId: string) => {
  return mutate<{ derived_count: number }>(request, `
    mutation {
      timelineRegenerate(containerId: ${JSON.stringify(containerId)}) { derived_count }
    }
  `, 'timelineRegenerate');
};

export const addTimelineContainment = async (request: APIRequestContext, containerId: string, title: string, eventTime: string) => {
  return mutate<{ id: string }>(request, `
    mutation {
      timelineEventAdd(input: {
        container_id: ${JSON.stringify(containerId)},
        event_time: ${JSON.stringify(eventTime)},
        title: ${JSON.stringify(title)},
        kind: containment,
        lane: response
      }) { id }
    }
  `, 'timelineEventAdd');
};

export const deleteTimelineCase = async (request: APIRequestContext, timelineCase: TimelineCase) => {
  const ids = [timelineCase.taskId, timelineCase.caseId, timelineCase.malwareId];
  for (let index = 0; index < ids.length; index += 1) {
    await graphqlQuery(request, `mutation { stixCoreObjectEdit(id: ${JSON.stringify(ids[index])}) { delete } }`);
  }
};
