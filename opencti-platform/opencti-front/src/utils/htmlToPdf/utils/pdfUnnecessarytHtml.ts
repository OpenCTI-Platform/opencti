/**
 * There are some tags we don't want in the generated PDF.
 *
 * @param content The content to analyse.
 * @returns Content without necessary stuff.
 */
const removeUnnecessaryHtml = (content: string) => {
  return content
    .replaceAll('id="undefined" ', '') // ???
    .replaceAll(/<img[^>]+src=(\\?["'])[^'"]+\.gif\1[^>]*\/?>/gi, ''); // Remove GIFs from content.
};

export default removeUnnecessaryHtml;
