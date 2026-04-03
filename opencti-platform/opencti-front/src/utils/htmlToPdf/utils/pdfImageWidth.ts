import { TIPTAP_EDITOR_SELECTOR, CKEDITOR_CONTAINER_SELECTOR, MAX_WIDTH_PORTRAIT } from './constants';

/**
 * Find images and apply a width in pixels on it.
 *
 * We have several cases that can happened:
 * - An image with a width in pixels => ensure width is not to big.
 * - An image with a width in percent => convert to pixels.
 * - An image inside a figure with a width in pixels => set width to image.
 * - An image inside a figure with a width in percent => convert to pixels and set to image.
 * - An image without any size => make it full width.
 *
 * @param content The content of the file.
 * @returns New content with images widths in pixels.
 */
const setImagesWidth = (content: string, maxWidth = MAX_WIDTH_PORTRAIT, isTiptapEnabled = false) => {
  let updatedContent = content;
  const selector = isTiptapEnabled ? TIPTAP_EDITOR_SELECTOR : CKEDITOR_CONTAINER_SELECTOR;
  const elementEditor = document.querySelector(selector);
  const fullWidth = elementEditor ? (elementEditor as HTMLElement).clientWidth : maxWidth;

  // 1. In case of images with width in pixels.
  // Find the value of the width and max sure it is not higher than maximum possible.
  updatedContent = updatedContent.replaceAll(
    /<img.+?width="([0-9\\.]+)".*?>/gi,
    (match, width) => {
      let result = match;
      if (width > maxWidth) {
        result = result.replace(/ height="\d+"/, ''); // Clear height to keep ratio.
        result = result.replace(`width="${width}"`, `width="${maxWidth}"`);
      }
      return result;
    },
  );

  // 2. In case of images with width in percentage.
  // Transform the width percentage in pixels.
  updatedContent = updatedContent.replaceAll(
    /<img.+?style=".*?width:([0-9\\.]+%).*?".*?>/gi,
    (match, width) => {
      const widthValue = width.split('%')[0];
      const widthInPixels = (fullWidth * widthValue) / 100;
      return match.replace(width, `${widthInPixels}px`);
    },
  );

  // 3. In case of figures with width in percentages
  // containing images, need to also apply the size on the image.
  updatedContent = updatedContent.replaceAll(
    /<figure.+?style=".*?width:([0-9\\.]+%).*?".*?>.*?<\/figure>/gi,
    (match, width) => {
      const widthValue = width.split('%')[0];
      const widthInPixels = (fullWidth * widthValue) / 100;
      let result = match;
      result = result.replace(/ width="\d+"/, '');
      result = result.replace(/ height="\d+"/, '');
      return result.replace('<img ', `<img width="${widthInPixels}" `);
    },
  );

  // 4. In case of figures with width in pixels
  // containing images, need to also apply the size on the image.
  updatedContent = updatedContent.replaceAll(
    /<figure.+?style=".*?width:([0-9\\.]+px).*?".*?>.*?<\/figure>/gi,
    (match, width) => {
      let widthValue = width.split('px')[0];
      if (widthValue > maxWidth) widthValue = maxWidth;
      let result = match;
      result = result.replace(/ width="\d+"/, '');
      result = result.replace(/ height="\d+"/, '');
      return result.replace('<img ', `<img width="${widthValue}" `);
    },
  );

  // 5. In case of images without any size.
  // (/!\ it is important to have this test after all others).
  // Make it full width.
  updatedContent = updatedContent.replaceAll(
    /(<img(?![^>]*\swidth=")(?![^>]*\bwidth:)[^>]*>)/gi, // check width attribute AND width ins tyle attribute.
    (match) => match.replace('<img ', `<img width="${maxWidth}" `),
  );

  return updatedContent;
};

export default setImagesWidth;
