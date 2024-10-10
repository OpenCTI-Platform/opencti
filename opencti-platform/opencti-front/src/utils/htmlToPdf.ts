import { renderToString } from 'react-dom/server';
import { compiler } from 'markdown-to-jsx';
import htmlToPdfmake from 'html-to-pdfmake';
import pdfMake from 'pdfmake/build/pdfmake';
import { TDocumentDefinitions } from 'pdfmake/interfaces';
import { APP_BASE_PATH } from '../relay/environment';

/**
 * Transform html file into a PDF that can be downloaded.
 * @param fileName name of the file to transform.
 * @param content The content of the file.
 */
const htmlToPdf = (fileName: string, content: string) => {
  console.log(content);
  // Remove some content we don't want in the PDF.
  let htmlData = content
    .replaceAll('id="undefined" ', '') // ???
    .replaceAll(/<img[^>]+src=(\\?["'])[^'"]+\.gif\1[^>]*\/?>/gi, ''); // Remove GIFs from content.

  // Improve render for markdown files.
  if (fileName.endsWith('.md')) {
    htmlData = renderToString(compiler(htmlData, { wrapper: null }));
  }

  const pdfObject = htmlToPdfmake(htmlData, {
    imagesByReference: true,
    ignoreStyles: ['font-family'],
  }) as unknown as TDocumentDefinitions;
  console.log(pdfObject);

  // Prepare fonts to use Roboto.
  const { protocol, hostname, port } = window.location;
  const url = `${protocol}//${hostname}:${port || ''}`;
  const fonts = {
    Roboto: {
      normal: `${url}${APP_BASE_PATH}/static/ext/Roboto-Regular.ttf`,
      bold: `${url}${APP_BASE_PATH}/static/ext/Roboto-Bold.ttf`,
      italics: `${url}${APP_BASE_PATH}/static/ext/Roboto-Italic.ttf`,
      bolditalics: `${url}${APP_BASE_PATH}/static/ext/Roboto-BoldItalic.ttf`,
    },
  };

  return pdfMake.createPdf(pdfObject, undefined, fonts);
};

export default htmlToPdf;
