/**
 * There are some tags we don't want in the generated PDF.
 * This function cleans up HTML content to ensure proper PDF generation.
 *
 * @param content The content to analyse.
 * @returns Content without unnecessary stuff but preserving article body.
 */
const removeUnnecessaryHtml = (content: string) => {
  let cleanedContent = content
    .replaceAll('id="undefined" ', '') // Remove undefined IDs
    .replaceAll(/<img[^>]+src=(\\?["'])[^'"]+\.gif\1[^>]*\/?>/gi, ''); // Remove GIFs from content

  // Remove script tags and their content
  cleanedContent = cleanedContent.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');

  // Remove style tags and their content (inline styles on elements are preserved)
  cleanedContent = cleanedContent.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '');

  // Remove iframe tags
  cleanedContent = cleanedContent.replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '');

  // Remove noscript tags
  cleanedContent = cleanedContent.replace(/<noscript\b[^<]*(?:(?!<\/noscript>)<[^<]*)*<\/noscript>/gi, '');

  // Remove comments
  cleanedContent = cleanedContent.replace(/<!--[\s\S]*?-->/g, '');

  // Remove empty class attributes
  cleanedContent = cleanedContent.replace(/\s+class=""\s*/g, ' ');

  // Remove empty style attributes
  cleanedContent = cleanedContent.replace(/\s+style=""\s*/g, ' ');

  // Clean up multiple consecutive whitespace (but preserve single spaces and newlines)
  cleanedContent = cleanedContent.replace(/[ \t]+/g, ' ');

  return cleanedContent;
};

export default removeUnnecessaryHtml;
