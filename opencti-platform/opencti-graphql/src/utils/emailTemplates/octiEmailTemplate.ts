import { HEADER_TEMPLATE } from './header';
import { FOOTER_TEMPLATE } from './footer';
import { LOGO_TEMPLATE } from './logo';

export const OCTI_EMAIL_TEMPLATE = `
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
                                          <div style="padding: 20px;">
                                            <%- body %>
                                          </div>
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
`;
