import { CKEDITOR_CONTAINER_SELECTOR, MAX_WIDTH_PORTRAIT } from './constants';

/**
 * Find images and apply a width in pixels on it.
 * We have several cases that can happened:
 * - An image with a width in pixels => nothing to do.
 * - An image with a width in percent => convert to pixels.
 * - An image inside a figure with a width in pixels => set width to image.
 * - An image inside a figure with a width in percent => convert to pixels and set to image.
 *
 * @param content The content of the file.
 * @returns New content with images widths in pixels.
 */
const setImagesWidth = (content: string) => {
  const elementCkEditor = document.querySelector(CKEDITOR_CONTAINER_SELECTOR);
  const fullWidth = elementCkEditor ? elementCkEditor.clientWidth : MAX_WIDTH_PORTRAIT;

  let updatedContent = content;
  // In case of images with percentage.
  updatedContent = updatedContent.replaceAll(/<img.+?style=".*?width:([0-9\\.]+%).*?".*?>/gi, (match, width) => {
    const widthValue = width.split('%')[0];
    const widthInPixels = (fullWidth * widthValue) / 100;
    return match.replace(width, `${widthInPixels}px`);
  });
  // In case of figures containing images, need to also apply the size on the image.
  updatedContent = updatedContent.replaceAll(/<figure.+?style=".*?width:([0-9\\.]+%).*?".*?>.*?<\/figure>/gi, (match, width) => {
    const widthValue = width.split('%')[0];
    const widthInPixels = (fullWidth * widthValue) / 100;
    return match.replace('<img src="', `<img width="${widthInPixels}" src="`);
  });
  // In case of figures with pixels containing images, need to also apply the size on the image.
  updatedContent = updatedContent.replaceAll(/<figure.+?style=".*?width:([0-9\\.]+px).*?".*?>.*?<\/figure>/gi, (match, width) => {
    const widthValue = width.split('px')[0];
    return match.replace('<img src="', `<img width="${widthValue}" src="`);
  });
  return updatedContent;
};

export default setImagesWidth;
