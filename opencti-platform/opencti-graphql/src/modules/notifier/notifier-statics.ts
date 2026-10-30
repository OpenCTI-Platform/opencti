import type { JSONSchemaType } from 'ajv';
import type { NotifierConnector } from '../../generated/graphql';
import { type BasicStoreEntityNotifier, ENTITY_TYPE_NOTIFIER } from './notifier-types';
import { HEADER_TEMPLATE } from '../../utils/emailTemplates/header';
import { FOOTER_TEMPLATE } from '../../utils/emailTemplates/footer';
import { LOGO_TEMPLATE } from '../../utils/emailTemplates/logo';
import { ABSTRACT_BASIC_OBJECT, ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { INGESTION_HEALTH_FEATURE_FLAG, isFeatureEnabled } from '../../config/conf';

// region Notifier User interface
export const NOTIFIER_CONNECTOR_UI = 'f39b8ab2c-8f5c-4167-a249-229f34d9442b';
// endregion
// region Notifier Email
export const NOTIFIER_CONNECTOR_EMAIL = '6f5e30a8-56d5-4ff1-8b8d-f90243f771dc';
export const NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL = '9f73d9f8-cc4c-432b-b5b0-be6b6d6c8d87';

export interface NOTIFIER_CONNECTOR_EMAIL_INTERFACE {
  title: string;
  template: string;
  url_suffix: string;
}

export interface NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL_INTERFACE {
  title: string;
  header: string;
  logo: string;
  footer: string;
  background_color: string;
  url_suffix: string;
}

export const NOTIFIER_CONNECTOR_EMAIL_CONFIG: JSONSchemaType<NOTIFIER_CONNECTOR_EMAIL_INTERFACE> = {
  type: 'object',
  properties: {
    title: { type: 'string' },
    template: { type: 'string' },
    url_suffix: { type: 'string' },
  },
  required: ['title', 'template'],
};
export const NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL_CONFIG: JSONSchemaType<NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL_INTERFACE> = {
  type: 'object',
  properties: {
    title: { type: 'string' },
    header: { type: 'string' },
    logo: { type: 'string' },
    footer: { type: 'string' },
    background_color: { type: 'string' },
    url_suffix: { type: 'string' },
  },
  required: ['title'],
};
// endregion
// region Notifier Webhook
export const NOTIFIER_CONNECTOR_WEBHOOK = '08f9f00f-4e52-4466-ae27-be9fa9813a88';

export interface NOTIFIER_CONNECTOR_WEBHOOK_INTERFACE {
  verb: string;
  url: string;
  template: string;
  params: { attribute: string; value: string }[];
  headers: { attribute: string; value: string }[];
}

export const NOTIFIER_CONNECTOR_WEBHOOK_CONFIG: JSONSchemaType<NOTIFIER_CONNECTOR_WEBHOOK_INTERFACE> = {
  type: 'object',
  properties: {
    verb: { type: 'string', enum: ['GET', 'POST', 'PUT', ' DELETE'] },
    url: { type: 'string' },
    template: { type: 'string' },
    params: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          attribute: {
            type: 'string',
          },
          value: {
            type: 'string',
          },
        },
        required: ['attribute', 'value'],
      },
    },
    headers: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          attribute: {
            type: 'string',
          },
          value: {
            type: 'string',
          },
        },
        required: ['attribute', 'value'],
      },
    },
  },
  required: ['url', 'verb', 'template'],
};

// endregion

export const BUILTIN_NOTIFIERS_CONNECTORS: Record<string, NotifierConnector> = {
  [NOTIFIER_CONNECTOR_EMAIL]: {
    id: NOTIFIER_CONNECTOR_EMAIL,
    connector_type: 'Notifier',
    name: 'Platform mailer',
    built_in: true,
    connector_schema: JSON.stringify(NOTIFIER_CONNECTOR_EMAIL_CONFIG),
    connector_schema_ui: JSON.stringify({
      template: {
        'ui:widget': 'textarea',
        'ui:options': {
          rows: 20,
        },
      },
    }),
  },
  [NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL]: {
    id: NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL,
    connector_type: 'Notifier',
    name: 'Simple mailer',
    built_in: true,
    connector_schema: JSON.stringify(NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL_CONFIG),
    connector_schema_ui: JSON.stringify({
      logo: {
        'ui:widget': 'file',
        'ui:options': { accept: 'image/*' }, // Because of an open bug: this is not working yet https://github.com/rjsf-team/react-jsonschema-form/issues/3577
      },
      background_color: {
        'ui:widget': 'color', // Same, for now we can't have fully customized components, we will need to investigate in the future
      },
    }),
  },
  [NOTIFIER_CONNECTOR_WEBHOOK]: {
    id: NOTIFIER_CONNECTOR_WEBHOOK,
    connector_type: 'Notifier',
    name: 'Generic webhook',
    built_in: true,
    connector_schema: JSON.stringify(NOTIFIER_CONNECTOR_WEBHOOK_CONFIG),
    connector_schema_ui: JSON.stringify({
      template: {
        'ui:widget': 'textarea',
        'ui:options': {
          rows: 20,
        },
      },
    }),
  },
};

export const STATIC_NOTIFIER_UI = 'f4ee7b33-006a-4b0d-b57d-411ad288653d';
export const STATIC_NOTIFIER_EMAIL = '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822';

// region Notifier Health email
export const STATIC_NOTIFIER_HEALTH_EMAIL = '19b97b2d-9fa5-496b-95b6-3f3703c9a959';

// For the ingestion health activity events: the scope, the ingestion and a link to its overview (the front resolveLink routes)
// A live alert with one event: its scope and its ingestion. Otherwise: how many sources need attention and how many recovered
export const HEALTH_EMAIL_TITLE = '<% const healthEvents = notification_content.reduce((allEvents, contentLine) => allEvents.concat(contentLine.events), []); %>'
  + '<% const attentionCount = healthEvents.filter((contentEvent) => contentEvent.operation !== \'recovered\').length; %>'
  + '<% const normalCount = healthEvents.length - attentionCount; %>'
  + '<% const isDigest = notification.trigger_type === \'digest\'; %>'
  + '<% const subjectPrefix = isDigest ? \'[digest]\' : \'[live]\'; %>'
  + '<% const scopeLabels = { critical: \'Critical\', degraded: \'Degraded\', recovered: \'Recovered\' }; %>'
  + '<% const subjectParts = []; %>'
  + '<% if (attentionCount > 0) { subjectParts.push(attentionCount + (attentionCount === 1 ? \' source needs\' : \' sources need\') + \' attention\'); } %>'
  + '<% if (normalCount > 0) { subjectParts.push(normalCount + \' recovered\'); } %>'
  + '<% if (!isDigest && healthEvents.length === 1) { %><%= subjectPrefix %> <%= scopeLabels[healthEvents[0].operation] || healthEvents[0].operation %> — <%= notification_content[0].title %>'
  + '<% } else { %><%= subjectPrefix %> Ingestion health — <%= subjectParts.join(\', \') %><% } %>';

export const HEALTH_EMAIL_TEMPLATE = `
${HEADER_TEMPLATE}
<%
  const healthScopeLabels = { critical: 'Critical', degraded: 'Degraded', recovered: 'Recovered', stopped: 'Stopped' };
  const healthScopeStyles = {
    critical: 'background-color: #fdecea; border: 1px solid #f5c2c0; color: #c62828;',
    degraded: 'background-color: #fff3e0; border: 1px solid #fcd9a8; color: #b45309;',
    recovered: 'background-color: #e8f5e9; border: 1px solid #b9dfbc; color: #2e7d32;',
    stopped: 'background-color: #f1f3f5; border: 1px solid #d5dae0; color: #5f6b7a;',
  };
  /* The box of a live alert, by scope */
  const healthBoxStyles = {
    critical: 'background-color: #fdecea; border-left: 4px solid #d32f2f;',
    degraded: 'background-color: #fff3e0; border-left: 4px solid #ed6c02;',
    recovered: 'background-color: #e8f5e9; border-left: 4px solid #2e7d32;',
    stopped: 'background-color: #f1f3f5; border-left: 4px solid #757575;',
  };
  const healthBoxTitles = { critical: ' is critical', degraded: ' is degraded', recovered: ' has recovered', stopped: ' was stopped' };
  /* The status an event ends on: a recovery is back to healthy */
  const healthScopeStatuses = { critical: 'critical', degraded: 'degraded', recovered: 'healthy' };
  const healthStatusLabels = { healthy: 'Healthy', degraded: 'Degraded', critical: 'Critical', unknown: 'Unknown' };
  const ingestionTypeLabels = {
    Connector: 'Connector',
    Sync: 'Sync',
    IngestionRss: 'RSS feed',
    IngestionTaxii: 'TAXII feed',
    IngestionTaxiiCollection: 'TAXII push feed',
    IngestionCsv: 'CSV feed',
    IngestionJson: 'JSON feed',
  };
  const ingestionViewLabels = { Connector: 'connector', Sync: 'sync' };
  /* Same routes as resolveLink in opencti-front/src/utils/Entity.ts, without /dashboard: keep both in sync */
  const ingestionPaths = {
    Connector: 'integrations/connectors',
    Sync: 'integrations/feeds/sync',
    IngestionRss: 'integrations/feeds/rss',
    IngestionTaxii: 'integrations/feeds/taxii',
    IngestionTaxiiCollection: 'integrations/feeds/taxii-push',
    IngestionCsv: 'integrations/feeds/csv',
    IngestionJson: 'integrations/feeds/json',
  };
  const periodLabels = { hour: 'Hourly', day: 'Daily', week: 'Weekly', month: 'Monthly' };
  const isDigest = notification.trigger_type === 'digest';
  const triggerLabel = isDigest ? (periodLabels[notification.period] || 'Periodic') + ' digest' : 'Live alert';
  const formatHealthDate = (date) => new Date(date).toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC' }) + ' UTC';
  /* What the health manager put in the context of the event: the details of the failure, the status reported before, and since when the current one lasts */
  const readHealthEvent = (contentEvent) => {
    const eventData = data.find((entry) => entry.instance && entry.instance.id === contentEvent.instance_id && entry.type === contentEvent.operation);
    const eventInstance = (eventData && eventData.instance) || {};
    const statusChange = eventInstance.ingestion_health_changes || {};
    const criticalMessages = statusChange.critical_messages || [];
    const advisoryMessages = statusChange.advisory_messages || [];
    /* The box lists the issues of the criticity of the email, the advisory ones of a critical email come below it */
    const issues = contentEvent.operation === 'critical' ? criticalMessages : advisoryMessages;
    const advisoryIssues = contentEvent.operation === 'critical' ? advisoryMessages : [];
    /* The digest shows the first issue only, followed by how many others there are */
    const allIssues = issues.concat(advisoryIssues);
    const digestMessage = allIssues.length > 0 ? allIssues[0] + (allIssues.length > 1 ? ' (+' + (allIssues.length - 1) + ')' : '') : statusChange.message;
    return { eventMessage: statusChange.message, digestMessage, issues, advisoryIssues, previousStatus: statusChange.previous_status, statusSince: statusChange.status_since, endStatus: healthScopeStatuses[contentEvent.operation] };
  };
  const sourceIds = {};
  notification_content.forEach((contentLine) => contentLine.events.forEach((contentEvent) => { sourceIds[contentEvent.instance_id] = true; }));
  const sourceCount = Object.keys(sourceIds).length;
%>
   <body leftmargin="0" marginwidth="0" topmargin="0" marginheight="0" offset="0" bgcolor="#e4e9f1" style="margin: 0; padding: 0; font-family: Helvetica, Arial, sans-serif; font-size: 16px; width: 100%; min-width: 100%;">
      <table border="0" cellpadding="0" cellspacing="0" width="100%" bgcolor="#e4e9f1" style="font-family: Helvetica, Arial, sans-serif; font-size: 16px; color: #425b76; line-height: 1.5; width: 100%; min-width: 100%; background-color: #e4e9f1;">
         <tbody>
            <tr>
               <td align="center" valign="top" style="padding: 20px 0;">
                  <table border="0" cellpadding="0" cellspacing="0" width="700" bgcolor="#ffffff" style="width: 700px; background-color: #ffffff;" class="emailWrapper">
                     <tbody>
                        <tr>
                           <td style="height: 4px; background-color: #001bda; font-size: 4px; line-height: 4px;">&nbsp;</td>
                        </tr>
                        <tr>
                           <td align="center" valign="middle" class="logo">
                              ${LOGO_TEMPLATE}
                           </td>
                        </tr>
                        <tr>
                           <td align="center" valign="top">
                              <table border="0" cellpadding="0" cellspacing="0" width="560" style="width: 560px;" class="emailContainer">
                                 <tbody>
                                    <tr>
                                       <td align="center" valign="middle" style="padding: 30px 0; border-top: 1px solid #eaf0f6; border-bottom: 1px solid #eaf0f6;">
                                          <h1 style="font-size: 24px; font-weight: 600; margin: 0;"><%= settings.platform_title %></h1>
                                          <p style="font-size: 15px; margin: 10px 0 0 0;">Ingestion health &middot; <%= triggerLabel %><% if (isDigest) { %> &middot; <%= formatHealthDate(new Date()) %><% } %></p>
                                       </td>
                                    </tr>
                                    <% if (isDigest) { %>
                                    <tr>
                                       <td valign="top" style="padding: 30px 0 20px 0;">
                                          <p style="margin: 0 0 25px 0;"><%= sourceCount %> ingestion source<%= sourceCount === 1 ? '' : 's' %> changed health status<% if (periodLabels[notification.period]) { %> in the last <%= notification.period %><% } %>.</p>
                                          <p style="font-weight: 600; margin: 0;">Ingestion health (<%= triggerLabel.toLowerCase() %>)</p>
                                       </td>
                                    </tr>
                                    <% notification_content.forEach((contentLine) => { %>
                                      <% contentLine.events.forEach((contentEvent) => { %>
                                        <% const healthEvent = readHealthEvent(contentEvent); %>
                                        <tr>
                                           <td valign="top" style="padding: 18px 0; border-top: 1px solid #eaf0f6; line-height: 1.4;">
                                              <table border="0" cellpadding="0" cellspacing="0" width="100%" style="width: 100%;">
                                                 <tbody>
                                                    <tr>
                                                       <td valign="top">
                                                          <span style="display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: 700; text-transform: uppercase; <%= healthScopeStyles[contentEvent.operation] || healthScopeStyles.stopped %>"><%= healthScopeLabels[contentEvent.operation] || contentEvent.operation %></span>
                                                          <span style="margin-left: 8px; font-weight: 600;"><%= contentLine.title %></span>
                                                          <span style="margin-left: 5px; font-size: 13px;">(<%= ingestionTypeLabels[contentEvent.entity_type] || contentEvent.entity_type %>)</span>
                                                          <% if (healthEvent.digestMessage) { %>
                                                            <div style="margin-top: 8px;"><%= healthEvent.digestMessage %></div>
                                                          <% } %>
                                                          <% if (healthEvent.endStatus) { %>
                                                            <div style="margin-top: 8px; font-size: 13px; color: #516f90;">
                                                               <i>Status:</i> <% if (healthEvent.previousStatus) { %><%= healthStatusLabels[healthEvent.previousStatus] || healthEvent.previousStatus %> &rarr; <% } %><%= healthStatusLabels[healthEvent.endStatus] %>
                                                               <% if (healthEvent.statusSince) { %> &nbsp;&middot;&nbsp; <i>Detected:</i> <%= formatHealthDate(healthEvent.statusSince) %><% } %>
                                                            </div>
                                                          <% } %>
                                                       </td>
                                                       <td width="60" align="right" valign="top">
                                                          <% if (contentEvent.instance_id) { %>
                                                            <a href="<%= platform_uri %>/dashboard/<%= ingestionPaths[contentEvent.entity_type] || 'id' %>/<%= contentEvent.instance_id %>?source=email" target="_blank" style="display: inline-block; border: 1px solid #cbd6e2; border-radius: 3px; background-color: #eaf0f6; color: #425b76; font-size: 12px; line-height: 12px; padding: 8px 12px; text-decoration: none; white-space: nowrap;">View</a>
                                                          <% } %>
                                                       </td>
                                                    </tr>
                                                 </tbody>
                                              </table>
                                           </td>
                                        </tr>
                                      <% }) %>
                                    <% }) %>
                                    <tr>
                                       <td style="border-top: 1px solid #eaf0f6; font-size: 1px; line-height: 1px; padding-bottom: 30px;">&nbsp;</td>
                                    </tr>
                                    <% } else { %>
                                    <% notification_content.forEach((contentLine) => { %>
                                      <% contentLine.events.forEach((contentEvent) => { %>
                                        <% const healthEvent = readHealthEvent(contentEvent); %>
                                        <tr>
                                           <td valign="top" style="padding: 30px 0 0 0;">
                                              <table border="0" cellpadding="0" cellspacing="0" width="100%" style="width: 100%; border-radius: 3px; <%= healthBoxStyles[contentEvent.operation] || healthBoxStyles.stopped %>">
                                                 <tbody>
                                                    <tr>
                                                       <td valign="top" style="padding: 20px; line-height: 1.4;">
                                                          <span style="display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: 700; text-transform: uppercase; <%= healthScopeStyles[contentEvent.operation] || healthScopeStyles.stopped %>"><%= healthScopeLabels[contentEvent.operation] || contentEvent.operation %></span>
                                                          <% if (healthEvent.statusSince) { %><span style="margin-left: 8px; font-size: 14px;">Detected <%= formatHealthDate(healthEvent.statusSince) %></span><% } %>
                                                          <h2 style="font-size: 22px; font-weight: 600; margin: 12px 0 0 0;"><%= contentLine.title %><%= healthBoxTitles[contentEvent.operation] || '' %></h2>
                                                          <% if (healthEvent.issues.length === 1) { %>
                                                            <p style="margin: 10px 0 0 0;"><%= healthEvent.issues[0] %></p>
                                                          <% } else if (healthEvent.issues.length > 1) { %>
                                                            <ul style="margin: 10px 0 0 0; padding-left: 20px;">
                                                              <% healthEvent.issues.forEach((issue) => { %>
                                                                <li style="margin: 4px 0;"><%= issue %></li>
                                                              <% }) %>
                                                            </ul>
                                                          <% } else if (healthEvent.eventMessage) { %>
                                                            <p style="margin: 10px 0 0 0;"><%= healthEvent.eventMessage %></p>
                                                          <% } %>
                                                       </td>
                                                    </tr>
                                                 </tbody>
                                              </table>
                                           </td>
                                        </tr>
                                        <% if (healthEvent.advisoryIssues.length > 0) { %>
                                        <tr>
                                           <td valign="top" style="padding: 20px 0 0 0; line-height: 1.4;">
                                              <p style="margin: 0; font-size: 16px; font-weight: 600;">Advisory issues</p>
                                              <% if (healthEvent.advisoryIssues.length === 1) { %>
                                                <p style="margin: 8px 0 0 0;"><%= healthEvent.advisoryIssues[0] %></p>
                                              <% } else { %>
                                                <ul style="margin: 8px 0 0 0; padding-left: 20px;">
                                                   <% healthEvent.advisoryIssues.forEach((issue) => { %>
                                                     <li style="margin: 4px 0;"><%= issue %></li>
                                                   <% }) %>
                                                </ul>
                                              <% } %>
                                           </td>
                                        </tr>
                                        <% } %>
                                        <tr>
                                           <td valign="top" style="padding: 25px 0 0 0;">
                                              <table border="0" cellpadding="0" cellspacing="0" width="100%" style="width: 100%; font-size: 15px;">
                                                 <tbody>
                                                    <tr>
                                                       <td width="200" valign="top" style="padding: 12px 0; border-bottom: 1px solid #eaf0f6;">Source</td>
                                                       <td valign="top" style="padding: 12px 0; border-bottom: 1px solid #eaf0f6; font-weight: 600;"><%= contentLine.title %> (<%= ingestionTypeLabels[contentEvent.entity_type] || contentEvent.entity_type %>)</td>
                                                    </tr>
                                                    <% if (healthEvent.endStatus) { %>
                                                    <tr>
                                                       <td width="200" valign="top" style="padding: 12px 0; border-bottom: 1px solid #eaf0f6;"><%= healthEvent.previousStatus ? 'Status change' : 'Status' %></td>
                                                       <td valign="top" style="padding: 12px 0; border-bottom: 1px solid #eaf0f6; font-weight: 600;"><% if (healthEvent.previousStatus) { %><%= healthStatusLabels[healthEvent.previousStatus] || healthEvent.previousStatus %> &rarr; <% } %><%= healthStatusLabels[healthEvent.endStatus] %></td>
                                                    </tr>
                                                    <% } %>
                                                 </tbody>
                                              </table>
                                           </td>
                                        </tr>
                                        <% if (contentEvent.instance_id) { %>
                                        <tr>
                                           <td align="center" valign="top" style="padding: 30px 0 0 0;">
                                              <a href="<%= platform_uri %>/dashboard/<%= ingestionPaths[contentEvent.entity_type] || 'id' %>/<%= contentEvent.instance_id %>?source=email" target="_blank" style="display: inline-block; border-radius: 3px; background-color: #001bda; color: #ffffff; font-size: 16px; padding: 16px 30px; text-decoration: none; white-space: nowrap;">View <%= ingestionViewLabels[contentEvent.entity_type] || 'feed' %></a>
                                           </td>
                                        </tr>
                                        <% } %>
                                      <% }) %>
                                    <% }) %>
                                    <tr>
                                       <td align="center" valign="top" style="padding: 20px 0 0 0; font-size: 15px;">
                                          <a href="<%= platform_uri %>/dashboard/integrations/deployed?health=critical,degraded" target="_blank" style="color: #001bda; text-decoration: none;">See all sources that need attention →</a>
                                       </td>
                                    </tr>
                                    <tr>
                                       <td align="center" valign="top" style="padding: 30px 0 40px 0; font-size: 13px; color: #516f90;">
                                          <% if (notification.name) { %>You receive this email because you subscribed to the trigger &ldquo;<%= notification.name %>&rdquo;. <% } %><a href="<%= platform_uri %>/dashboard/settings/activity/alerting" target="_blank" style="color: #001bda; text-decoration: none;">Manage your notifications</a>.
                                       </td>
                                    </tr>
                                    <% } %>
                                 </tbody>
                              </table>
                           </td>
                        </tr>
                     </tbody>
                  </table>
                  <table border="0" cellpadding="0" cellspacing="0" width="700" style="width: 700px;">
                     <tbody>
                        <tr>
                           <td>
                              ${FOOTER_TEMPLATE}
                           </td>
                        </tr>
                     </tbody>
                  </table>
               </td>
            </tr>
         </tbody>
      </table>
   </body>
</html>
`;

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
const STATIC_HEALTH_EMAIL_NOTIFIER: BasicStoreEntityNotifier = {
  id: STATIC_NOTIFIER_HEALTH_EMAIL,
  standard_id: `notifier--${STATIC_NOTIFIER_HEALTH_EMAIL}`,
  entity_type: ENTITY_TYPE_NOTIFIER,
  parent_types: [ABSTRACT_BASIC_OBJECT, ABSTRACT_INTERNAL_OBJECT],
  internal_id: STATIC_NOTIFIER_HEALTH_EMAIL,
  built_in: true,
  name: 'Ingestion health default mailer',
  description: 'Send ingestion health activity events to the user email',
  notifier_connector_id: NOTIFIER_CONNECTOR_EMAIL,
  notifier_configuration: JSON.stringify({ title: HEALTH_EMAIL_TITLE, template: HEALTH_EMAIL_TEMPLATE }),
};
// endregion

export const STATIC_NOTIFIERS: Array<BasicStoreEntityNotifier> = [
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  {
    id: STATIC_NOTIFIER_UI,
    standard_id: `notifier--${STATIC_NOTIFIER_UI}`,
    entity_type: ENTITY_TYPE_NOTIFIER,
    parent_types: [ABSTRACT_BASIC_OBJECT, ABSTRACT_INTERNAL_OBJECT],
    internal_id: STATIC_NOTIFIER_UI,
    built_in: true,
    name: 'User interface',
    description: 'Publish notification to the user interface',
    notifier_connector_id: NOTIFIER_CONNECTOR_UI,
    notifier_configuration: '',
  },
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  {
    id: STATIC_NOTIFIER_EMAIL,
    standard_id: `notifier--${STATIC_NOTIFIER_EMAIL}`,
    entity_type: ENTITY_TYPE_NOTIFIER,
    parent_types: [ABSTRACT_BASIC_OBJECT, ABSTRACT_INTERNAL_OBJECT],
    internal_id: STATIC_NOTIFIER_EMAIL,
    built_in: true,
    name: 'Default mailer',
    description: 'Send notification to the user email',
    notifier_connector_id: NOTIFIER_CONNECTOR_EMAIL,
    notifier_configuration: JSON.stringify({
      title: '<% if(notification.trigger_type === \'live\'){ %>\n'
        + '[<%=notification.trigger_type%>] <%= notification_content[0].title %>'
        + ' <% } else{ %>  \n'
        + '[<%=notification.trigger_type%>] <%= notification.name%>'
        + '<% } %>',
      template: `
${HEADER_TEMPLATE}
   <body leftmargin="0" marginwidth="0" topmargin="0" marginheight="0" offset="0" bgcolor="#f5f8fa" style="-webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; margin: 0; padding:0; font-family: Helvetica, Arial, sans-serif; font-size: 16px; height: 100%; width: 100%; min-width: 100%;">
      <table id="outerWrapper" border="0" cellpadding="0" cellspacing="0" height="100%" width="100%" bgcolor="#f5f8fa" style="font-family: Helvetica, Arial, sans-serif; font-size:16px; color: #425b76; line-height: 1.5; width: 100%; min-width: 100%; background-color:#f5f8fa;">
         <tbody>
            <tr>
               <td align="center" valign="top">
                  <table border="0" cellpadding="0" cellspacing="0" width="700" bgcolor="#ffffff" opacity="1" style="width: 700px; background-color:#ffffff;" class="emailWrapper">
                     <tbody>
                        <tr>
                           <td align="center" valign="top" width="100%" bgcolor="#ffffff" style="width: 100%; min-width: 100%; background-color:#ffffff;">
                              <table cellpadding="0" border="0" cellspacing="0" width="100%" style="width: 100%; min-width:100%;">
                                 <tbody>
                                    <tr>
                                      <td cellpadding="0" align="center" valign="middle" width="100%" style="height: 4px; background-color: #001bda; width: 100%; min-width:100%; font-size:4px; line-height: 4px;"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span></td>
                                    </tr>
                                    <tr>
                                      <td align="center" valign="middle" width="100%" style="width: 100%; min-width:100%;" class="logo">
                                        ${LOGO_TEMPLATE}
                                      </td>
                                    </tr>
                                 </tbody>
                              </table>
                              <table border="0" cellpadding="0" cellspacing="0" width="500" bgcolor="#ffffff" style="width: 500px; background-color:#ffffff;" class="emailContainer">
                                 <tbody>
                                    <tr>
                                       <td align="left" valign="top" width="100%" style="width: 100%; min-width: 100%;">
                                          <hr style="height: 1px; color: #eaf0f6; background-color: #eaf0f6; border: none; margin: 0px; padding: 0px;">
                                          <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 15px; width: 100%; min-width: 100%; line-height: 0;">
                                             <tbody>
                                                <tr>
                                                   <td height="15"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span>
                                                   </td>
                                                </tr>
                                             </tbody>
                                          </table>
                                          <table cellpadding="0" border="0" cellspacing="0" width="100%" style="color: #425b76; font-size: 20px; width: 100%; margin: initial; min-width: 100%;">
                                             <tbody>
                                                <tr>
                                                   <td align="center" valign="middle" style="padding: 0; ">
                                                      <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 10px; width: 100%; min-width: 100%; line-height: 0;">
                                                         <tbody>
                                                            <tr>
                                                               <td height="10"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span>
                                                               </td>
                                                            </tr>
                                                         </tbody>
                                                      </table>
                                                      <h1 style="font-size: 24px; font-weight: 600; margin: 0; text-align: center"><%=settings.platform_title%></h1>
                                                      <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 20px; width: 100%; min-width: 100%; line-height: 0;">
                                                         <tbody>
                                                            <tr>
                                                               <td height="20"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span>
                                                               </td>
                                                            </tr>
                                                         </tbody>
                                                      </table>
                                                      <table border="0" cellpadding="0" cellspacing="0" width="100%"style="font-size: 0; height: 30px; width: 100%; min-width: 100%; line-height: 0;">
                                                         <tbody>
                                                            <tr>
                                                               <td height="30"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width:100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size:0;"> &nbsp;</span>
                                                               </td>
                                                            </tr>
                                                         </tbody>
                                                      </table>
                                                      <hr style="height: 1px; color: #eaf0f6; background-color: #eaf0f6; border: none; margin: 0px; padding: 0px;">
                                                      <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 30px; width: 100%; min-width: 100%; line-height: 0;">
                                                         <tbody>
                                                            <tr>
                                                               <td height="30"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span>
                                                               </td>
                                                            </tr>
                                                         </tbody>
                                                      </table>
                                                   </td>
                                                </tr>
                                             </tbody>
                                          </table>
                                          <% notification_content.forEach((contentLine)=> { %>
                                            <table cellpadding="0" border="0" cellspacing="0" width="100%" style="color: #425b76; font-size: 20px; width: 100%; margin: initial; min-width: 100%;">
                                               <tbody>
                                                  <tr>
                                                     <td align="center" valign="middle" style="padding: 0; ">
                                                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 20px; width: 100%; min-width: 100%; line-height: 0;">
                                                           <tbody>
                                                              <tr>
                                                                 <td height="20"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span>
                                                                 </td>
                                                              </tr>
                                                           </tbody>
                                                        </table>
                                                        <h3 style="font-size: 15px; font-weight: 600; margin: 0; text-align: left"><%= contentLine.title %></h3>
                                                        <table border="0" cellpadding="0" cellspacing="0" width="100%"style="font-size: 0; height: 15px; width: 100%; min-width: 100%; line-height: 0;">
                                                           <tbody>
                                                              <tr>
                                                                 <td height="15"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width:100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size:0;"> &nbsp;</span>
                                                                 </td>
                                                              </tr>
                                                           </tbody>
                                                        </table>
                                                        <hr style="height: 1px; color: #eaf0f6; background-color: #eaf0f6; border: none; margin: 0px; padding: 0px;">
                                                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 10px; width: 100%; min-width: 100%; line-height: 0;">
                                                           <tbody>
                                                              <tr>
                                                                 <td height="10"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span>
                                                                 </td>
                                                              </tr>
                                                           </tbody>
                                                        </table>
                                                     </td>
                                                  </tr>
                                               </tbody>
                                            </table>
                                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 10px; width: 100%; min-width: 100%; line-height: 0;">
                                               <tbody>
                                                  <tr>
                                                     <td height="10"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height: 1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;">&nbsp;</span>
                                                     </td>
                                                  </tr>
                                               </tbody>
                                            </table>
                                            <% contentLine.events.forEach((contentEvent)=> { %>
                                              <table width="100%" border="0" cellspacing="0" cellpadding="0" style="border-bottom: 1px solid #eaf0f6; margin-bottom: 20px;">
                                                 <tbody>
                                                    <tr>
                                                       <td valign="top" style="line-height: 1.4; padding-bottom: 20px; min-width:310px;">
                                                          <%= contentEvent.message %>
                                                          <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 5px; width: 100%; min-width: 100%; line-height: 0;">
                                                             <tbody>
                                                                <tr>
                                                                   <td height="5"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span>
                                                                   </td>
                                                                </tr>
                                                             </tbody>
                                                          </table>
                                                          <section style="font-size: 12px">
                                                             <span style="margin-right: 10px; display: inline-block;">
                                                                <span style="font-style: italic;">Operation:</span> <%= contentEvent.operation %>
                                                             </span>
                                                          </section>
                                                       </td>
                                                       <td width="20" valign="top" style="font-size: 1px; min-width: 20px;"></td>
                                                       <td width="50" valign="top">
                                                          <table width="100%" border="0" cellspacing="0" cellpadding="0" style="width: 100%; min-width: 100%;">
                                                             <tbody>
                                                                <tr>
                                                                   <td align="center">
                                                                      <table border="0" cellspacing="0" cellpadding="0">
                                                                         <tbody>
                                                                            <tr>
                                                                               <td align="center" style="border-radius: 3px;" bgcolor="#eaf0f6" width="30px">
                                                                               <% if(contentEvent.instance_id && contentEvent.operation !== 'delete') {%>
                                                                                    <a href="<%=platform_uri%>/dashboard/id/<%= contentEvent.instance_id %>?source=email&<%=url_suffix%>" target="_blank" style="border: 1px solid #eaf0f6; border-radius: 3px; color: #FFFFFF; display: inline-block; font-size: 14px; font-weight: 400; line-height: 1; padding: 12px 20px; text-decoration: none; width: 30px; min-width: 30px; white-space: nowrap; border: 1px solid #cbd6e2; color: #425b76; height: 12px; padding: 8px 12px; font-size: 12px; line-height: 12px;">View</a>
                                                                               <% } %>
                                                                               </td>
                                                                            </tr>
                                                                         </tbody>
                                                                      </table>
                                                                   </td>
                                                                </tr>
                                                             </tbody>
                                                          </table>
                                                       </td>
                                                    </tr>
                                                 </tbody>
                                              </table>
                                              <% }) %>
                                          <% }) %>
                                          <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 50px; width: 100%; min-width: 100%; line-height: 0;">
                                             <tbody>
                                                <tr>
                                                   <td height="50"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none;text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span>
                                                   </td>
                                                </tr>
                                             </tbody>
                                          </table>
                                       </td>
                                    </tr>
                                 </tbody>
                              </table>
                           </td>
                        </tr>
                        <tr>
                           <td>
                              ${FOOTER_TEMPLATE}
                           </td>
                        </tr>
                     </tbody>
                  </table>
               </td>
            </tr>
         </tbody>
      </table>
   </body>
</html>
      `,
    }),
  },
  ...(isFeatureEnabled(INGESTION_HEALTH_FEATURE_FLAG) ? [STATIC_HEALTH_EMAIL_NOTIFIER] : []),
];

export const SIMPLIFIED_EMAIL_TEMPLATE = `
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<% function parseMarkdownLink(text) {
  if (!text) {
    return '';
  }
  const regex = /(.*)\\[(.*?)\\]\\((.*?)\\)/;
  const match = text.match(regex);
  if (match) {
    const text = match[1];
    const linkText = match[2].split(' ').map((e) => escape(e)).join(' ');
    const linkUrl = match[3].split(' ').map((e) => escape(e)).join(' ');
    return text + '<a style="color:#fff; text-decoration:underline;" href="' + linkUrl +'">' + linkText + '</a>';
  }
  return text; // If it's not a link, return the original text
} %>
<html>
   <head>
      <meta content="en-us" http-equiv="Content-Language">
      <meta content="text/html; charset=utf-8" http-equiv="Content-Type">
      <title>Cyber Threat Intelligence Digest</title>
      <style type="text/css">
         #outlook a {
         padding: 0;
         }
         .ReadMsgBody{
         width:100%;
         }
         .ExternalClass{
         width: 100%;
         }
         .ExternalClass, .ExternalClass p, .ExternalClass span, .ExternalClass font, .ExternalClass td, .ExternalClass div {
         line-height: 100%;
         }
         body, table, td, p, a, li, blockquote{
         -webkit-text-size-adjust :100%; 
         -ms-text-size-adjust: 100%;
         }
         table, td {
         mso-table-lspace: 0pt; 
         mso-table-rspace: 0pt;
         }
         img{
         -ms-interpolation-mode: bicubic;
         }
         * {
         font-family: 'Arial';
         }
         body {
         margin: 0;
         padding: 0;
         background-color: #f8f8f8;
         background: #f8f8f8;
         }
      </style>
   </head>
   <body leftmargin="0" marginwidth="0" topmargin="0" marginheight="0" offset="0" bgcolor="#f5f8fa" style="-webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; margin: 0; padding:0; font-family: Helvetica, Arial, sans-serif; font-size: 16px; height: 100%; width: 100%; min-width: 100%;">
      <table id="outerWrapper" border="0" cellpadding="0" cellspacing="0" height="100%" width="100%" bgcolor="#f5f8fa" style="font-family: Helvetica, Arial, sans-serif; font-size:16px; color: #425b76; line-height: 1.5; width: 100%; min-width: 100%; background-color:#f5f8fa;">
         <tbody>
            <tr>
               <td align="center" valign="top">
                  <table border="0" cellpadding="0" cellspacing="0" width="700" bgcolor="#ffffff" opacity="1" style="width: 700px; background-color:#ffffff;" class="emailWrapper">
                     <tbody>
                        <tr>
                           <td align="center" valign="top" width="100%" bgcolor="#ffffff" style="width: 100%; min-width: 100%; background-color:#ffffff;">
                              <table cellpadding="0" border="0" cellspacing="0" width="100%" style="width: 100%; min-width:100%;">
                                 <tbody>
                                    <tr>
                                       <td cellpadding="0" align="center" valign="middle" width="100%" style="height: 4px; background-color: <%=background_color%>; width: 100%; min-width:100%; font-size:4px; line-height: 4px;"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span></td>
                                    </tr>
                                    <tr>
                                       <td align="center" valign="middle" width="100%" style="width: 100%; min-width:100%;" class="logo"><img src="<%=logo%>" alt="OpenCTI" width="250" style="vertical-align: middle; clear: both; width: 250px; max-width: 250px; padding-top: 40px; padding-bottom: 40px;"></td>
                                    </tr>
                                 </tbody>
                              </table>
                              <table border="0" cellpadding="0" cellspacing="0" width="500" bgcolor="#ffffff" style="width: 500px; background-color:#ffffff;" class="emailContainer">
                                 <tbody>
                                    <tr>
                                       <td align="left" valign="top" width="100%" style="width: 100%; min-width: 100%;">
                                          <hr style="height: 1px; color: #eaf0f6; background-color: #eaf0f6; border: none; margin: 0px; padding: 0px;">
                                          <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 15px; width: 100%; min-width: 100%; line-height: 0;">
                                             <tbody>
                                                <tr>
                                                   <td height="15"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span>
                                                   </td>
                                                </tr>
                                             </tbody>
                                          </table>
                                          <table cellpadding="0" border="0" cellspacing="0" width="100%" style="color: #425b76; font-size: 20px; width: 100%; margin: initial; min-width: 100%;">
                                             <tbody>
                                                <tr>
                                                   <td align="center" valign="middle" style="padding: 0; ">
                                                      <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 10px; width: 100%; min-width: 100%; line-height: 0;">
                                                         <tbody>
                                                            <tr>
                                                               <td height="10"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span>
                                                               </td>
                                                            </tr>
                                                         </tbody>
                                                      </table>
                                                      <h1 style="font-size: 24px; font-weight: 600; margin: 0; text-align: center"><%=settings.platform_title%></h1>
                                                      <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 20px; width: 100%; min-width: 100%; line-height: 0;">
                                                         <tbody>
                                                            <tr>
                                                               <td height="20"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span>
                                                               </td>
                                                            </tr>
                                                         </tbody>
                                                      </table>
                                                      <h2 style="font-size: 18px; font-weight: 400; margin: 0; text-align: center"><%- parseMarkdownLink(header)%></h2>
                                                      <table border="0" cellpadding="0" cellspacing="0" width="100%"style="font-size: 0; height: 30px; width: 100%; min-width: 100%; line-height: 0;">
                                                         <tbody>
                                                            <tr>
                                                               <td height="30"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width:100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size:0;"> &nbsp;</span>
                                                               </td>
                                                            </tr>
                                                         </tbody>
                                                      </table>
                                                      <hr style="height: 1px; color: #eaf0f6; background-color: #eaf0f6; border: none; margin: 0px; padding: 0px;">
                                                      <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 30px; width: 100%; min-width: 100%; line-height: 0;">
                                                         <tbody>
                                                            <tr>
                                                               <td height="30"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span>
                                                               </td>
                                                            </tr>
                                                         </tbody>
                                                      </table>
                                                   </td>
                                                </tr>
                                             </tbody>
                                          </table>
                                          <% notification_content.forEach((contentLine)=> { %>
                                            <table cellpadding="0" border="0" cellspacing="0" width="100%" style="color: #425b76; font-size: 20px; width: 100%; margin: initial; min-width: 100%;">
                                               <tbody>
                                                  <tr>
                                                     <td align="center" valign="middle" style="padding: 0; ">
                                                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 20px; width: 100%; min-width: 100%; line-height: 0;">
                                                           <tbody>
                                                              <tr>
                                                                 <td height="20"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span>
                                                                 </td>
                                                              </tr>
                                                           </tbody>
                                                        </table>
                                                        <h3 style="font-size: 15px; font-weight: 600; margin: 0; text-align: left"><%= contentLine.title %></h3>
                                                        <table border="0" cellpadding="0" cellspacing="0" width="100%"style="font-size: 0; height: 15px; width: 100%; min-width: 100%; line-height: 0;">
                                                           <tbody>
                                                              <tr>
                                                                 <td height="15"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width:100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size:0;"> &nbsp;</span>
                                                                 </td>
                                                              </tr>
                                                           </tbody>
                                                        </table>
                                                        <hr style="height: 1px; color: #eaf0f6; background-color: #eaf0f6; border: none; margin: 0px; padding: 0px;">
                                                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 10px; width: 100%; min-width: 100%; line-height: 0;">
                                                           <tbody>
                                                              <tr>
                                                                 <td height="10"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span>
                                                                 </td>
                                                              </tr>
                                                           </tbody>
                                                        </table>
                                                     </td>
                                                  </tr>
                                               </tbody>
                                            </table>
                                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 10px; width: 100%; min-width: 100%; line-height: 0;">
                                               <tbody>
                                                  <tr>
                                                     <td height="10"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height: 1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;">&nbsp;</span>
                                                     </td>
                                                  </tr>
                                               </tbody>
                                            </table>
                                            <% contentLine.events.forEach((contentEvent)=> { %>
                                              <table width="100%" border="0" cellspacing="0" cellpadding="0" style="border-bottom: 1px solid #eaf0f6; margin-bottom: 20px;">
                                                 <tbody>
                                                    <tr>
                                                       <td valign="top" style="line-height: 1.4; padding-bottom: 20px; min-width:310px;">
                                                          <%= contentEvent.message %>
                                                          <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 5px; width: 100%; min-width: 100%; line-height: 0;">
                                                             <tbody>
                                                                <tr>
                                                                   <td height="5"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span>
                                                                   </td>
                                                                </tr>
                                                             </tbody>
                                                          </table>
                                                          <section style="font-size: 12px">
                                                             <span style="margin-right: 10px; display: inline-block;">
                                                                <span style="font-style: italic;">Operation:</span> <%= contentEvent.operation %>
                                                             </span>
                                                          </section>
                                                       </td>
                                                       <td width="20" valign="top" style="font-size: 1px; min-width: 20px;"></td>
                                                       <td width="50" valign="top">
                                                          <table width="100%" border="0" cellspacing="0" cellpadding="0" style="width: 100%; min-width: 100%;">
                                                             <tbody>
                                                                <tr>
                                                                   <td align="center">
                                                                      <table border="0" cellspacing="0" cellpadding="0">
                                                                         <tbody>
                                                                            <tr>
                                                                               <td align="center" style="border-radius: 3px;" bgcolor="#eaf0f6" width="30px">
                                                                               <% if(contentEvent.instance_id && contentEvent.operation !== 'delete') {%>
                                                                                    <a href="<%=platform_uri%>/dashboard/id/<%= contentEvent.instance_id %>?source=email&<%=url_suffix%>" target="_blank" style="border: 1px solid #eaf0f6; border-radius: 3px; color: #FFFFFF; display: inline-block; font-size: 14px; font-weight: 400; line-height: 1; padding: 12px 20px; text-decoration: none; width: 30px; min-width: 30px; white-space: nowrap; border: 1px solid #cbd6e2; color: #425b76; height: 12px; padding: 8px 12px; font-size: 12px; line-height: 12px;">View</a>
                                                                               <% } %>
                                                                               </td>
                                                                            </tr>
                                                                         </tbody>
                                                                      </table>
                                                                   </td>
                                                                </tr>
                                                             </tbody>
                                                          </table>
                                                       </td>
                                                    </tr>
                                                 </tbody>
                                              </table>
                                              <% }) %>
                                          <% }) %>
                                          <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 0; height: 50px; width: 100%; min-width: 100%; line-height: 0;">
                                             <tbody>
                                                <tr>
                                                   <td height="50"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none;text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span>
                                                   </td>
                                                </tr>
                                             </tbody>
                                          </table>
                                       </td>
                                    </tr>
                                 </tbody>
                              </table>
                           </td>
                        </tr>
                        <tr>
                           <td>
                              <table id="footer" border="0" cellpadding="0" cellspacing="0" height="100%" width="100%" bgcolor="#f5f8fa" style="width: 100%; min-width: 100%;">
                                 <tbody>
                                    <tr>
                                       <td align="center" valign="top">
                                          <table border="0" cellpadding="0" cellspacing="0" height="100%" width="500" style="width: 500px;">
                                             <tbody>
                                                <tr>
                                                   <td align="center" valign="top">
                                                      <table cellpadding="0" border="0" cellspacing="0" width="100%" style="color: #425b76; background-color: ; font-size: 14px; width: 100%; margin: initial; min-width: 100%; line-height: 24px">
                                                         <tbody>
                                                            <tr>
                                                               <td align="center" valign="middle" style="padding: 5px 0 65px;">
                                                                  <p style="font-size: 12px; color: #516f90"><%- parseMarkdownLink(footer)%><br>Copyright &copy; 2025 OpenCTI<br>Powered by <a style="color: #001bda; text-decoration:none;" href="https://filigran.io" target="_blank">Filigran</a></p>
                                                               </td>
                                                            </tr>
                                                         </tbody>
                                                      </table>
                                                   </td>
                                                </tr>
                                             </tbody>
                                          </table>
                                       </td>
                                    </tr>
                                 </tbody>
                              </table>
                           </td>
                        </tr>
                     </tbody>
                  </table>
               </td>
            </tr>
         </tbody>
      </table>
   </body>
</html>
`;

export const DEFAULT_TEAM_MESSAGE = {
  notifier_connector_id: NOTIFIER_CONNECTOR_WEBHOOK,
  name: 'Sample of Microsoft Teams message for live trigger',
  description: 'This is a sample notifier to send a Microsoft Teams message. The template is already filled and fully customizable. You need to add the correct Microsoft Teams endpoint to get it working.',
  notifier_configuration: `
    {
      "template": "{\\n        \\"type\\": \\"message\\",\\n        \\"attachments\\": [\\n            {\\n                \\"contentType\\": \\"application/vnd.microsoft.card.thumbnail\\",\\n                \\"content\\": {\\n                    \\"subtitle\\": \\"Operation : <%=notification_content[0].events[0].operation%>\\",\\n                    \\"text\\": \\"<%=(new Date(notification.created)).toLocaleString()%>\\",\\n                    \\"title\\": \\"<%=notification_content[0].events[0].message%>\\",\\n                    \\"buttons\\": [\\n                        {\\n                            \\"type\\": \\"openUrl\\",\\n                            \\"title\\": \\"See in OpenCTI\\",\\n                            \\"value\\": \\"https://YOUR_OPENCTI_URL/dashboard/id/<%=notification_content[0].events[0].instance_id%>\\"\\n                        }\\n                    ]\\n                }\\n            }\\n        ]\\n    }",
      "url": "https://YOUR_DOMAIN.webhook.office.com/YOUR_ENDPOINT",
      "verb": "POST"
    }
  `,
};

export const DEFAULT_TEAM_DIGEST_MESSAGE = {
  notifier_connector_id: NOTIFIER_CONNECTOR_WEBHOOK,
  name: 'Sample of Microsoft Teams message for digest trigger',
  description: 'This is a sample notifier to send a Microsoft Teams message. The template is already filled and fully customizable. You need to add the correct Microsoft Teams endpoint to get it working.',
  notifier_configuration: `
    {
      "template": "{\\n    \\"type\\": \\"message\\",\\n    \\"attachments\\": [\\n        {\\n            \\"contentType\\": \\"application/vnd.microsoft.card.adaptive\\",\\n            \\"content\\": {\\n                \\"$schema\\": \\"http://adaptivecards.io/schemas/adaptive-card.json\\",\\n                \\"type\\": \\"AdaptiveCard\\",\\n                \\"version\\": \\"1.0\\",\\n                \\"body\\": [\\n                    {\\n                        \\"type\\": \\"Container\\",\\n                        \\"items\\": [\\n                            {\\n                                \\"type\\": \\"TextBlock\\",\\n                                \\"text\\": \\"<%=notification.name%>\\",\\n                                \\"weight\\": \\"bolder\\",\\n                                \\"size\\": \\"extraLarge\\"\\n                            }, {\\n                                \\"type\\": \\"TextBlock\\",\\n                                \\"text\\": \\"<%=(new Date(notification.created)).toLocaleString()%>\\",\\n                                \\"size\\": \\"medium\\"\\n                            }\\n                        ]\\n                    },\\n                    <% for(var i=0; i<notification_content.length; i++) { %>\\n                    {\\n                        \\"type\\": \\"Container\\",\\n                        \\"items\\": [<% for(var j=0; j<notification_content[i].events.length; j++) { %>\\n                            {\\n                                \\"type\\" : \\"TextBlock\\",\\n                                \\"text\\" : \\"[<%=notification_content[i].events[j].message%>](https://localhost:3000/dashboard/id/<%=notification_content[i].events[j].instance_id%>)\\"\\n                         \\t}<% if(j<(notification_content[i].events.length - 1)) {%>,<% } %>\\n                        <% } %>]\\n\\t\\t   }<% if(i<(notification_content.length - 1)) {%>,<% } %>\\n                    <% } %>\\n                ]\\n            }\\n        }\\n    ],\\n   \\"dataString\\": <%-JSON.stringify(notification)%>\\n}",
      "url": "https://YOUR_DOMAIN.webhook.office.com/YOUR_ENDPOINT",
      "verb": "POST"
    }
  `,
};
