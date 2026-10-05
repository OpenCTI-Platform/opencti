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
  indicatorId: string;
  platformId: string;
}

/**
 * An incident response holding a malware seen over three days, an indicator sighted by a security platform
 * (a detection) and a task due two days after the opening, with its timeline derived once. Demo values only.
 */
export const addTimelineCase = async (request: APIRequestContext, name: string, malwareName: string, taskName: string, codename: string): Promise<TimelineCase> => {
  // Documentation range (RFC 5737), one address per run so that concurrent runs never share the indicator
  const address = `198.51.100.${1 + Math.floor(Math.random() * 254)}`;
  const malware = await mutate<{ id: string }>(request, `
    mutation {
      malwareAdd(input: {
        name: ${JSON.stringify(malwareName)},
        first_seen: "2026-02-01T09:00:00.000Z",
        last_seen: "2026-02-04T09:00:00.000Z"
      }) { id }
    }
  `, 'malwareAdd');
  const indicator = await mutate<{ id: string }>(request, `
    mutation {
      indicatorAdd(input: {
        name: ${JSON.stringify(address)},
        pattern: ${JSON.stringify(`[ipv4-addr:value = '${address}']`)},
        pattern_type: "stix",
        x_opencti_main_observable_type: "IPv4-Addr",
        valid_from: "2026-02-02T08:00:00.000Z",
        valid_until: "2026-02-06T08:00:00.000Z"
      }) { id }
    }
  `, 'indicatorAdd');
  const platform = await mutate<{ id: string }>(request, `
    mutation {
      securityPlatformAdd(input: { name: ${JSON.stringify(`${codename} SIEM`)}, security_platform_type: "SIEM" }) { id }
    }
  `, 'securityPlatformAdd');
  const sighting = await mutate<{ id: string }>(request, `
    mutation {
      stixSightingRelationshipAdd(input: {
        fromId: ${JSON.stringify(indicator.id)},
        toId: ${JSON.stringify(platform.id)},
        first_seen: "2026-02-03T07:30:00.000Z",
        last_seen: "2026-02-03T09:00:00.000Z",
        attribute_count: 3
      }) { id }
    }
  `, 'stixSightingRelationshipAdd');
  const caseIncident = await mutate<{ id: string }>(request, `
    mutation {
      caseIncidentAdd(input: {
        name: ${JSON.stringify(name)},
        created: "2026-02-04T12:00:00.000Z",
        objects: [${[malware.id, indicator.id, sighting.id].map((id) => JSON.stringify(id)).join(', ')}]
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
  return { caseId: caseIncident.id, malwareId: malware.id, taskId: task.id, indicatorId: indicator.id, platformId: platform.id };
};

/** A request for information holding some of the knowledge of a timeline case, with its timeline derived once. */
export const addTimelineRfi = async (request: APIRequestContext, name: string, objectIds: string[]) => {
  const rfi = await mutate<{ id: string }>(request, `
    mutation {
      caseRfiAdd(input: {
        name: ${JSON.stringify(name)},
        created: "2026-02-03T10:00:00.000Z",
        objects: [${objectIds.map((id) => JSON.stringify(id)).join(', ')}]
      }) { id }
    }
  `, 'caseRfiAdd');
  await regenerateTimeline(request, rfi.id);
  return rfi;
};

/** A report and a grouping holding some of the knowledge of a timeline case: containers without a timeline. */
export const addAnalysesWithoutTimeline = async (request: APIRequestContext, name: string, objectIds: string[]) => {
  const objects = objectIds.map((id) => JSON.stringify(id)).join(', ');
  const report = await mutate<{ id: string }>(request, `
    mutation {
      reportAdd(input: { name: ${JSON.stringify(name)}, published: "2026-02-05T10:00:00.000Z", objects: [${objects}] }) { id }
    }
  `, 'reportAdd');
  const grouping = await mutate<{ id: string }>(request, `
    mutation {
      groupingAdd(input: { name: ${JSON.stringify(name)}, context: "suspicious-activity", objects: [${objects}] }) { id }
    }
  `, 'groupingAdd');
  return { reportId: report.id, groupingId: grouping.id };
};

/** An incident without any dated knowledge yet: its timeline is in the first-use state. */
export const addEmptyIncident = async (request: APIRequestContext, name: string) => {
  return mutate<{ id: string }>(request, `mutation { incidentAdd(input: { name: ${JSON.stringify(name)} }) { id } }`, 'incidentAdd');
};

/** A custom dashboard showing the timeline widget of a case. */
export const addTimelineDashboard = async (request: APIRequestContext, name: string, containerId: string) => {
  const dashboard = await mutate<{ id: string }>(request, `mutation { workspaceAdd(input: { type: "dashboard", name: ${JSON.stringify(name)} }) { id } }`, 'workspaceAdd');
  const widgetId = 'case-timeline-widget';
  const manifest = {
    widgets: {
      [widgetId]: {
        id: widgetId,
        type: 'case-timeline',
        perspective: null,
        dataSelection: [],
        parameters: { container_id: containerId, timeline_window: 'fit' },
        layout: { i: widgetId, x: 0, y: 0, w: 12, h: 4, moved: false, static: false },
      },
    },
    config: {},
  };
  const encoded = Buffer.from(JSON.stringify(manifest)).toString('base64');
  await mutate(request, `
    mutation { workspaceFieldPatch(id: ${JSON.stringify(dashboard.id)}, input: [{ key: "manifest", value: [${JSON.stringify(encoded)}] }]) { id } }
  `, 'workspaceFieldPatch');
  return dashboard;
};

export const deleteWorkspace = async (request: APIRequestContext, id: string) => {
  await graphqlQuery(request, `mutation { workspaceDelete(id: ${JSON.stringify(id)}) }`);
};

export const deleteEntity = async (request: APIRequestContext, id: string) => {
  await graphqlQuery(request, `mutation { stixCoreObjectEdit(id: ${JSON.stringify(id)}) { delete } }`);
};

export const regenerateTimeline = async (request: APIRequestContext, containerId: string) => {
  return mutate<{ derived_count: number }>(request, `
    mutation {
      timelineRegenerate(containerId: ${JSON.stringify(containerId)}) { derived_count }
    }
  `, 'timelineRegenerate');
};

export const setTimelineLanes = async (request: APIRequestContext, containerId: string, lanes: string[]) => {
  return mutate<{ id: string }>(request, `
    mutation {
      timelineSettingsUpdate(containerId: ${JSON.stringify(containerId)}, input: { enabled_lanes: [${lanes.join(', ')}] }) { id }
    }
  `, 'timelineSettingsUpdate');
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
  const ids = [timelineCase.taskId, timelineCase.caseId, timelineCase.indicatorId, timelineCase.platformId, timelineCase.malwareId];
  for (let index = 0; index < ids.length; index += 1) {
    await graphqlQuery(request, `mutation { stixCoreObjectEdit(id: ${JSON.stringify(ids[index])}) { delete } }`);
  }
};

/** Back to the default overview layout of an entity type, as if no administrator had customized it. */
export const resetOverviewLayout = async (request: APIRequestContext, targetType: string) => {
  const setting = await mutate<{ id: string }>(request, `query { entitySettingByType(targetType: ${JSON.stringify(targetType)}) { id } }`, 'entitySettingByType');
  return mutate<{ id: string }[]>(request, `
    mutation {
      entitySettingsFieldPatch(ids: [${JSON.stringify(setting.id)}], input: [{ key: "overview_layout_customization", value: [] }]) { id }
    }
  `, 'entitySettingsFieldPatch');
};

/** Theme of the current user: the name of a platform theme, or the platform default. */
export const setUserTheme = async (request: APIRequestContext, themeName: string | null) => {
  let themeId = 'default';
  if (themeName) {
    const themes = await mutate<{ edges: { node: { id: string; name: string } }[] }>(request, `
      query { themes(search: ${JSON.stringify(themeName)}) { edges { node { id name } } } }
    `, 'themes');
    const theme = themes.edges.find(({ node }) => node.name === themeName);
    if (!theme) throw new Error(`Theme ${themeName} not found`);
    themeId = theme.node.id;
  }
  return mutate<{ id: string }>(request, `mutation { meEdit(input: [{ key: "theme", value: [${JSON.stringify(themeId)}] }]) { id } }`, 'meEdit');
};
