import type { JSONSchemaType } from 'ajv';
import type { NotifierConnector } from '../../generated/graphql';
import { type BasicStoreEntityNotifier, ENTITY_TYPE_NOTIFIER } from './notifier-types';
import { HEADER_TEMPLATE } from '../../utils/emailTemplates/header';
import { FOOTER_TEMPLATE } from '../../utils/emailTemplates/footer';
import { LOGO_TEMPLATE } from '../../utils/emailTemplates/logo';
import { ABSTRACT_BASIC_OBJECT, ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';

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
  },
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  {
    id: STATIC_NOTIFIER_EMAIL,
    standard_id: `notifier--${STATIC_NOTIFIER_UI}`,
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
