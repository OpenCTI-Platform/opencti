import { APP_BASE_PATH } from '../../../relay/environment';

const { protocol, hostname, port } = window.location;
const url = `${protocol}//${hostname}:${port || ''}`;

export const FONTS = {
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
  NotoSansJp: {
    normal: `${url}${APP_BASE_PATH}/static/ext/NotoSansJP-Regular.ttf`,
    bold: `${url}${APP_BASE_PATH}/static/ext/NotoSansJP-Bold.ttf`,
  },
  NotoSansKr: {
    normal: `${url}${APP_BASE_PATH}/static/ext/NotoSansKR-Regular.ttf`,
    bold: `${url}${APP_BASE_PATH}/static/ext/NotoSansKR-Bold.ttf`,
  },
};

const isJapanese = (htmlData: string) => /[\u3000-\u303F\u3040-\u309F\u30A0-\u30FF\uFF00-\uFFEF\u4E00-\u9FAF\u3400-\u4DBF]/.test(htmlData);
const isKorean = (htmlData: string) => /[\u1100-\u11FF\u3130-\u318F\uAC00-\uD7AF]/.test(htmlData);

export const detectLanguage = (htmlData: string) => {
  if (isJapanese(htmlData)) return 'NotoSansJp';
  if (isKorean(htmlData)) return 'NotoSansKr';
  return 'Roboto';
};
