export const cleanHtmlTags = (str?: string | null) => {
  return (str ?? '')
    .replace('```html', '')
    .replace('```', '')
    .replace(/<html[^>]*>/g, '') // Removes `<html>` with any attributes
    .replace('</html>', '')
    .replace(/<body[^>]*>/g, '') // Removes `<body>` with any attributes
    .replace('</body>', '')
    .trim();
};
