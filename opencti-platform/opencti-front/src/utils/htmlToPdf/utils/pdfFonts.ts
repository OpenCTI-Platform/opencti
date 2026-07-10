import { APP_BASE_PATH } from '../../../relay/environment';

const { protocol, hostname, port } = window.location;
const url = `${protocol}//${hostname}:${port || ''}`;

export const FONTS = {
  Roboto: {
    normal: `${url}${APP_BASE_PATH}/assets/static/Roboto-Regular.ttf`,
    bold: `${url}${APP_BASE_PATH}/assets/static/Roboto-Bold.ttf`,
    italics: `${url}${APP_BASE_PATH}/assets/static/Roboto-Italic.ttf`,
    bolditalics: `${url}${APP_BASE_PATH}/assets/static/Roboto-BoldItalic.ttf`,
  },
  Geologica: {
    normal: `${url}${APP_BASE_PATH}/assets/static/Geologica-Regular.ttf`,
    bold: `${url}${APP_BASE_PATH}/assets/static/Geologica-Bold.ttf`,
    italics: `${url}${APP_BASE_PATH}/assets/static/Geologica-Regular.ttf`,
    bolditalics: `${url}${APP_BASE_PATH}/assets/static/Geologica-Bold.ttf`,
  },
  IbmPlexSans: {
    normal: `${url}${APP_BASE_PATH}/assets/static/IBMPlexSans-Regular.ttf`,
    bold: `${url}${APP_BASE_PATH}/assets/static/IBMPlexSans-Bold.ttf`,
    italics: `${url}${APP_BASE_PATH}/assets/static/IBMPlexSans-RegularItalic.ttf`,
    bolditalics: `${url}${APP_BASE_PATH}/assets/static/IBMPlexSans-BoldItalic.ttf`,
  },
  NotoSansJp: {
    normal: `${url}${APP_BASE_PATH}/assets/static/NotoSansJP-Regular.ttf`,
    bold: `${url}${APP_BASE_PATH}/assets/static/NotoSansJP-Bold.ttf`,
  },
  NotoSansKr: {
    normal: `${url}${APP_BASE_PATH}/assets/static/NotoSansKR-Regular.ttf`,
    bold: `${url}${APP_BASE_PATH}/assets/static/NotoSansKR-Bold.ttf`,
  },
};

const isJapanese = (htmlData: string) => /[\u3000-\u303F\u3040-\u309F\u30A0-\u30FF\uFF00-\uFFEF\u4E00-\u9FAF\u3400-\u4DBF]/.test(htmlData);
const isKorean = (htmlData: string) => /[\u1100-\u11FF\u3130-\u318F\uAC00-\uD7AF]/.test(htmlData);

export const detectLanguage = (htmlData: string) => {
  if (isJapanese(htmlData)) return 'NotoSansJp';
  if (isKorean(htmlData)) return 'NotoSansKr';
  return 'Roboto';
};
