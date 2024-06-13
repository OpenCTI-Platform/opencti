import type { JSONSchemaType } from 'ajv';
import type { NotifierConnector } from '../../generated/graphql';
import type { BasicStoreEntityNotifier } from './notifier-types';

// region Notifier User interface
export const NOTIFIER_CONNECTOR_UI = 'f39b8ab2c-8f5c-4167-a249-229f34d9442b';
// endregion
// region Notifier Email
export const NOTIFIER_CONNECTOR_EMAIL = '6f5e30a8-56d5-4ff1-8b8d-f90243f771dc';
export const NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL = '9f73d9f8-cc4c-432b-b5b0-be6b6d6c8d87';

export interface NOTIFIER_CONNECTOR_EMAIL_INTERFACE {
  title: string
  template: string
}

export interface NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL_INTERFACE {
  title: string
  header: string
  logo: string
  footer: string
  background_color: string
}

export const NOTIFIER_CONNECTOR_EMAIL_CONFIG: JSONSchemaType<NOTIFIER_CONNECTOR_EMAIL_INTERFACE> = {
  type: 'object',
  properties: {
    title: { type: 'string' },
    template: { type: 'string' },
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
  },
  required: ['title'],
};
// endregion
// region Notifier Webhook
export const NOTIFIER_CONNECTOR_WEBHOOK = '08f9f00f-4e52-4466-ae27-be9fa9813a88';

export interface NOTIFIER_CONNECTOR_WEBHOOK_INTERFACE {
  verb: string
  url: string
  template: string
  params: { attribute: string, value: string }[],
  headers: { attribute: string, value: string }[],
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
        required: ['attribute', 'value']
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
        required: ['attribute', 'value']
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
      }
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
        'ui:options': { accept: 'image/*' } // Because of an open bug: this is not working yet https://github.com/rjsf-team/react-jsonschema-form/issues/3577
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
      }
    }),
  }
};

export const STATIC_NOTIFIER_UI = 'f4ee7b33-006a-4b0d-b57d-411ad288653d';
export const STATIC_NOTIFIER_EMAIL = '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822';

export const STATIC_NOTIFIERS: Array<BasicStoreEntityNotifier> = [
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  {
    id: STATIC_NOTIFIER_UI,
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
      template: `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
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
                                       <td cellpadding="0" align="center" valign="middle" width="100%" style="height: 4px; background-color: #001bda; width: 100%; min-width:100%; font-size:4px; line-height: 4px;"><span style="-webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; color: transparent; background: none; user-select: none; -moz-user-select: none; -ms-user-select:none; -webkit-user-select:none; text-overflow: ellipsis; opacity: 0; width:100%; min-width: 100%; height:1; overlfow:hidden; margin: -1px 0 0 0; padding:0; font-size: 0;"> &nbsp;</span></td>
                                    </tr>
                                    <tr>
                                       <td align="center" valign="middle" width="100%" style="width: 100%; min-width:100%;" class="logo"><img src="data:image/png;base64,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ZG9iZS5jb20veGFwLzEuMC8iCiAgIHhtcE1NOkRvY3VtZW50SUQ9ImdpbXA6ZG9jaWQ6Z2ltcDo2ZWViYzZlMi1hODY2LTRlYjktYmVkNS01MWRkYjhkODAxNDEiCiAgIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6YjgyMTE2ODYtZTMzZS00OTA3LThkY2YtMDBiNzYxNzlkY2UxIgogICB4bXBNTTpPcmlnaW5hbERvY3VtZW50SUQ9InhtcC5kaWQ6ZTM5NzZmMWItNzRiMi00YzZiLWI5NjMtNTUyNjI5MjVlYzNhIgogICBkYzpGb3JtYXQ9ImltYWdlL3BuZyIKICAgR0lNUDpBUEk9IjIuMCIKICAgR0lNUDpQbGF0Zm9ybT0iV2luZG93cyIKICAgR0lNUDpUaW1lU3RhbXA9IjE3MDkxMDIyMDYyMDk5ODYiCiAgIEdJTVA6VmVyc2lvbj0iMi4xMC4zMiIKICAgdGlmZjpPcmllbnRhdGlvbj0iMSIKICAgeG1wOkNyZWF0b3JUb29sPSJHSU1QIDIuMTAiCiAgIHhtcDpNZXRhZGF0YURhdGU9IjIwMjQ6MDI6MjhUMDc6MzY6NDUrMDE6MDAiCiAgIHhtcDpNb2RpZnlEYXRlPSIyMDI0OjAyOjI4VDA3OjM2OjQ1KzAxOjAwIj4KICAgPHhtcE1NOkhpc3Rvcnk+CiAgICA8cmRmOlNlcT4KICAgICA8cmRmOmxpCiAgICAgIHN0RXZ0OmFjdGlvbj0ic2F2ZWQiCiAgICAgIHN0RXZ0OmNoYW5nZWQ9Ii8iCiAgICAgIHN0RXZ0Omluc3RhbmNlSUQ9InhtcC5paWQ6NDVhOWU5N2QtMTc1YS00NDE0LTk0ZjUtM2QwMzA3NmYxYjc2IgogICAgICBzdEV2dDpzb2Z0d2FyZUFnZW50PSJHaW1wIDIuMTAgKFdpbmRvd3MpIgogICAgICBzdEV2dDp3aGVuPSIyMDI0LTAyLTI4VDA3OjM2OjQ2Ii8+CiAgICA8L3JkZjpTZXE+CiAgIDwveG1wTU06SGlzdG9yeT4KICA8L3JkZjpEZXNjcmlwdGlvbj4KIDwvcmRmOlJERj4KPC94OnhtcG1ldGE+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAg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" alt="OpenCTI" width="250" style="vertical-align: middle; clear: both; width: 250px; max-width: 250px; padding-top: 40px; padding-bottom: 40px;"></td>
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
                                                                               <td align="center" style="border-radius: 3px;" bgcolor="#eaf0f6" width="30px"><a href="<%=platform_uri%>/dashboard/id/<%= contentEvent.instance_id %>" target="_blank" style="border: 1px solid #eaf0f6; border-radius: 3px; color: #FFFFFF; display: inline-block; font-size: 14px; font-weight: 400; line-height: 1; padding: 12px 20px; text-decoration: none; width: 30px; min-width: 30px; white-space: nowrap; border: 1px solid #cbd6e2; color: #425b76; height: 12px; padding: 8px 12px; font-size: 12px; line-height: 12px;">View</a></td>
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
                                                                  <p style="font-size: 12px; color: #516f90">Copyright &copy; 2024 OpenCTI&reg;<br>Powered by <a style="color: #001bda; text-decoration:none;" href="https://filigran.io" target="_blank">Filigran</a></p>
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
      `
    })
  }
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
                                                                               <td align="center" style="border-radius: 3px;" bgcolor="#eaf0f6" width="30px"><a href="<%=platform_uri%>/dashboard/id/<%= contentEvent.instance_id %>" target="_blank" style="border: 1px solid #eaf0f6; border-radius: 3px; color: #FFFFFF; display: inline-block; font-size: 14px; font-weight: 400; line-height: 1; padding: 12px 20px; text-decoration: none; width: 30px; min-width: 30px; white-space: nowrap; border: 1px solid #cbd6e2; color: #425b76; height: 12px; padding: 8px 12px; font-size: 12px; line-height: 12px;">View</a></td>
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
                                                                  <p style="font-size: 12px; color: #516f90"><%- parseMarkdownLink(footer)%><br>Copyright &copy; 2024 OpenCTI&reg;<br>Powered by <a style="color: #001bda; text-decoration:none;" href="https://filigran.io" target="_blank">Filigran</a></p>
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
  `
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
  `
};
