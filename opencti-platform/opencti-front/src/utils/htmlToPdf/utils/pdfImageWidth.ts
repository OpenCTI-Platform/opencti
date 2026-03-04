import { CKEDITOR_CONTAINER_SELECTOR, MAX_WIDTH_PORTRAIT } from './constants';

/**
 * Find images and apply a width in pixels on it.
 *
 * We have several cases that can happened:
 * - An image with a width in pixels => ensure width is not to big.
 * - An image with a width in percent => convert to pixels.
 * - An image inside a figure with a width in pixels => set width to image.
 * - An image inside a figure with a width in percent => convert to pixels and set to image.
 *
 * @param content The content of the file.
 * @returns New content with images widths in pixels.
 */
const setImagesWidth = (content: string) => {
  let updatedContent = content;
  const elementCkEditor = document.querySelector(CKEDITOR_CONTAINER_SELECTOR);
  const fullWidth = elementCkEditor ? elementCkEditor.clientWidth : MAX_WIDTH_PORTRAIT;

  // 1. In case of images with width in pixels.
  // Find the value of the width and max sure it is not higher than maximum possible.
  updatedContent = updatedContent.replaceAll(
    /<img.+?width="([0-9\\.]+)".*?>/gi,
    (match, width) => {
      let result = match;
      if (width > MAX_WIDTH_PORTRAIT) {
        result = result.replace(/ height="\d+"/, ''); // Clear height to keep ratio.
        result = result.replace(`width="${width}"`, `width="${MAX_WIDTH_PORTRAIT}"`);
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
      if (widthValue > MAX_WIDTH_PORTRAIT) widthValue = MAX_WIDTH_PORTRAIT;
      let result = match;
      result = result.replace(/ width="\d+"/, '');
      result = result.replace(/ height="\d+"/, '');
      return result.replace('<img ', `<img width="${widthValue}" `);
    },
  );

  return updatedContent;
};

export default setImagesWidth;
