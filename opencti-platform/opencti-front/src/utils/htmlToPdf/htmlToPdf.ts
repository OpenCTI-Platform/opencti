import { renderToString } from 'react-dom/server';
import { compiler } from 'markdown-to-jsx';
import htmlToPdfmake from 'html-to-pdfmake';
import pdfMake from 'pdfmake/build/pdfmake';
import { Content, TDocumentDefinitions } from 'pdfmake/interfaces';
import { fileUri } from '../../relay/environment';
import { capitalizeWords } from '../String';
import logoWhite from '../../static/images/logo_text_white.png';
import { getBase64ImageFromURL } from '../Image';
import FONTS from './utils/pdfFonts';
import determineOrientation from './utils/pdfOrientation';
import setImagesWidth from './utils/pdfImageWidth';
import setTableFullWidth, { defaultTableLayout } from './utils/pdfTableWidth';
import addPageBreaks, { pdfPageBreaks } from './utils/pdfPageBreaks';
import removeUnnecessaryHtml from './utils/pdfUnnecessarytHtml';
import pdfBackground from './utils/pdfBackground';
import pdfHeader from './utils/pdfHeader';
import pdfFooter from './utils/pdfFooter';
import { DARK, GREY, WHITE } from './utils/constants';
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
 * @returns PDF object ready to be downloaded.
 */
export const htmlToPdfReport = async (reportName: string, content: string, templateName: string, markingNames: string[]) => {
  const formattedTemplateName = capitalizeWords(templateName);
  const logoBase64 = await getBase64ImageFromURL(fileUri(logoWhite));

  let htmlData = removeUnnecessaryHtml(content);
  htmlData = setImagesWidth(htmlData);
  htmlData = setTableFullWidth(htmlData);
  htmlData = addPageBreaks(htmlData);

  // Transform html string into a JS object that lib pdfmake can understand.
  const pdfMakeObject = htmlToPdfmake(htmlData, {
    removeExtraBlanks: true,
    imagesByReference: true,
    ignoreStyles: ['font-family'], // Ignoring fonts to force Roboto later.
    defaultStyles: {
      h2: { margin: [0, 20, 0, 10], color: DARK, fontSize: 28 },
      h3: { margin: [0, 20, 0, 10], color: DARK, fontSize: 24 },
      th: { bold: true, fillColor: '', font: 'Roboto' },
      td: { font: 'Roboto' },
    },
  }) as unknown as TDocumentDefinitions; // Because wrong type when using imagesByReference: true.

  const docDefinition: TDocumentDefinitions = {
    pageMargins: [20, 30],
    styles: {
      colorWhite: { color: WHITE },
      colorLight: { color: GREY },
      textMd: { fontSize: 14 },
      textXl: { fontSize: 40 },
      fontGeo: { font: 'Geologica' },
    },
    defaultStyle: {
      font: 'IbmPlexSans',
      fontSize: 12,
    },
    ...pdfMakeObject,
    content: [
      {
        columns: [
          {
            image: logoBase64,
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
        style: ['colorWhite', 'fontGeo', 'textXl'],
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
          linearGradient: ['#00020C', '#001BDA'],
        }],
      },
      {
        image: logoBase64,
        alignment: 'center',
        margin: [0, 380, 0, 0],
      },
    ],
    background: pdfBackground,
    header: pdfHeader,
    footer: pdfFooter(markingNames),
    pageBreakBefore: pdfPageBreaks,
  };

  return generatePdf(docDefinition);
};
