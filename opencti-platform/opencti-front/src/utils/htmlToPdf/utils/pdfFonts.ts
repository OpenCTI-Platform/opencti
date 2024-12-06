import { APP_BASE_PATH } from '../../../relay/environment';

const { protocol, hostname, port } = window.location;
const url = `${protocol}//${hostname}:${port || ''}`;

const FONTS = {
  Roboto: {
    normal: `${url}${APP_BASE_PATH}/static/ext/Roboto-Regular.ttf`,
    bold: `${url}${APP_BASE_PATH}/static/ext/Roboto-Bold.ttf`,
    italics: `${url}${APP_BASE_PATH}/static/ext/Roboto-Italic.ttf`,
    bolditalics: `${url}${APP_BASE_PATH}/static/ext/Roboto-BoldItalic.ttf`,
  },
  Geologica: {
    normal: `${url}${APP_BASE_PATH}/static/ext/Geologica-Regular.ttf`,
    bold: `${url}${APP_BASE_PATH}/static/ext/Geologica-Bold.ttf`,
    italics: `${url}${APP_BASE_PATH}/static/ext/Geologica-Regular.ttf`,
    bolditalics: `${url}${APP_BASE_PATH}/static/ext/Geologica-Bold.ttf`,
  },
  IbmPlexSans: {
    normal: `${url}${APP_BASE_PATH}/static/ext/IBMPlexSans-Regular.ttf`,
    bold: `${url}${APP_BASE_PATH}/static/ext/IBMPlexSans-Bold.ttf`,
    italics: `${url}${APP_BASE_PATH}/static/ext/IBMPlexSans-RegularItalic.ttf`,
    bolditalics: `${url}${APP_BASE_PATH}/static/ext/IBMPlexSans-BoldItalic.ttf`,
  },
};

export default FONTS;
