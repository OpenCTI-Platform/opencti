import { renderToString } from 'react-dom/server';
import { compiler } from 'markdown-to-jsx';
import htmlToPdfmake from 'html-to-pdfmake';
import pdfMake from 'pdfmake/build/pdfmake';
import { Content, TDocumentDefinitions } from 'pdfmake/interfaces';
import { FintelDesign } from '@components/common/form/FintelDesignField';
import { APP_BASE_PATH, fileUri } from '../../relay/environment';
import { capitalizeWords } from '../String';
import logoWhite from '../../static/images/logo_text_white.png';
import { getBase64ImageFromURL, isImageFromUrlSvg } from '../Image';
import { FONTS, detectLanguage } from './utils/pdfFonts';
import determineOrientation from './utils/pdfOrientation';
import setImagesWidth from './utils/pdfImageWidth';
import setTableFullWidth, { defaultTableLayout } from './utils/pdfTableWidth';
import addPageBreaks, { pdfPageBreaks } from './utils/pdfPageBreaks';
import removeUnnecessaryHtml from './utils/pdfUnnecessarytHtml';
import pdfBackground from './utils/pdfBackground';
import pdfHeader from './utils/pdfHeader';
import pdfFooter from './utils/pdfFooter';
import { DARK, DARK_BLUE, GREY, WHITE } from './utils/constants';
import { dateFormat } from '../Time';

/**
 * NOT MEANT FOR EXPORT
 *
 * Generate a PDF that can be downloaded.
 *
 * @param pdfMakeObject Definition of the PDF to generate.
 * @param checkOrientation True if check content to determine PDF orientation.
 * @returns PDF ready to be downloaded.
 */
const generatePdf = (pdfMakeObject: TDocumentDefinitions, checkOrientation = false) => {
  const docDefinition = { ...pdfMakeObject };
  if (checkOrientation) {
    docDefinition.pageOrientation = determineOrientation();
  }
  return pdfMake.createPdf(docDefinition, defaultTableLayout, FONTS);
};

/**
 * Transform html file into a PDF that can be downloaded.
 *
 * @param fileName name of the file to transform.
 * @param content The content of the file.
 * @returns PDF object ready to be downloaded.
 */
export const htmlToPdf = (fileName: string, content: string) => {
  let htmlData = removeUnnecessaryHtml(content);
  htmlData = setImagesWidth(htmlData);

  // Improve render for markdown files.
  if (fileName && fileName.endsWith('.md')) {
    htmlData = renderToString(compiler(htmlData, { wrapper: null }));
  }

  // Transform html string into a JS object that lib pdfmake can understand.
  const pdfMakeObject = htmlToPdfmake(htmlData, {
    imagesByReference: true,
    ignoreStyles: ['font-family'], // Ignoring fonts to force Roboto later.
  }) as unknown as TDocumentDefinitions; // Because wrong type when using imagesByReference: true.

  return generatePdf(pdfMakeObject);
};

/**
 * Transform html file into a PDF that can be downloaded.
 * /!\ Used for outcome templates reports.
 *
 * @param reportName Name the report outcome should have.
 * @param content HTML content.
 * @param templateName Name of the template used for PDF generation.
 * @param markingNames Markings of the outcome report.
 * @param fintelDesign Design of the template
 * @returns PDF object ready to be downloaded.
 */
export const htmlToPdfReport = async (
  reportName: string,
  content: string,
  templateName: string,
  markingNames: string[],
  fintelDesign?: FintelDesign | null | undefined,
) => {
  const formattedTemplateName = capitalizeWords(templateName);
  let logo;
  let isLogoSvg = false;

  if (fintelDesign?.file_id) {
    const url = `${APP_BASE_PATH}/storage/view/${encodeURIComponent(
      fintelDesign?.file_id,
    )}`;
    const { isSvg, content: svgContent } = await isImageFromUrlSvg(url);
    isLogoSvg = isSvg;
    if (!isLogoSvg) logo = await getBase64ImageFromURL(url);
    else logo = svgContent;
  }

  if (!logo) {
    logo = await getBase64ImageFromURL(fileUri(logoWhite));
  }

  let htmlData = removeUnnecessaryHtml(content);
  htmlData = setImagesWidth(htmlData);
  htmlData = setTableFullWidth(htmlData);
  htmlData = addPageBreaks(htmlData);

  const selectedFont = detectLanguage(htmlData);

  // Transform html string into a JS object that lib pdfmake can understand.
  const pdfMakeObject = htmlToPdfmake(htmlData, {
    removeExtraBlanks: true,
    imagesByReference: true,
    ignoreStyles: ['font-family'], // Ignoring fonts to force Roboto later.
    defaultStyles: {
      h2: { margin: [0, 20, 0, 10], color: DARK, fontSize: 28 },
      h3: { margin: [0, 20, 0, 10], color: DARK, fontSize: 24 },
      th: { bold: true, fillColor: '', font: selectedFont },
      td: { font: selectedFont },
    },
  }) as unknown as TDocumentDefinitions; // Because wrong type when using imagesByReference: true.

  const linearGradiant = [
    fintelDesign?.gradiantFromColor || DARK,
    fintelDesign?.gradiantToColor || DARK_BLUE,
  ];
  const textColor = fintelDesign?.textColor || WHITE;

  const docDefinition: TDocumentDefinitions = {
    pageMargins: [20, 30],
    styles: {
      colorWhite: { color: textColor },
      colorLight: { color: GREY },
      textMd: { fontSize: 14 },
      textXl: { fontSize: 40 },
      fontGeo: { font: 'Geologica' },
    },
    defaultStyle: {
      font: selectedFont,
      fontSize: 12,
    },
    ...pdfMakeObject,
    content: [
      {
        columns: [
          {
            image: !isLogoSvg ? logo : undefined,
            svg: isLogoSvg ? logo : undefined,
            width: 133,
          },
          {
            text: dateFormat(new Date()) ?? '',
            alignment: 'right',
            style: ['colorWhite'],
          },
        ],
      },
      {
        text: reportName,
        style: ['colorWhite', selectedFont, 'textXl'],
        marginTop: 200,
      },
      {
        text: formattedTemplateName,
        style: ['colorWhite', 'textMd'],
        marginTop: 10,
        pageBreak: 'after',
      },
      {
        stack: pdfMakeObject.content as Content[],
      },
      {
        pageBreak: 'before',
        absolutePosition: { x: 0, y: 0 },
        canvas: [{
          type: 'rect',
          x: 0,
          y: 0,
          w: 600,
          h: 850,
          linearGradient: linearGradiant,
        }],
      },
      {
        image: !isLogoSvg ? logo : undefined,
        svg: isLogoSvg ? logo : undefined,
        width: 133,
        alignment: 'center',
        margin: [0, 380, 0, 0],
      },
    ],
    background: pdfBackground(linearGradiant),
    header: pdfHeader(linearGradiant),
    footer: pdfFooter(markingNames),
    pageBreakBefore: pdfPageBreaks,
  };

  return generatePdf(docDefinition);
};
