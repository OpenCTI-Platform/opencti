export const cleanHtmlTags = (str: string) => {
  if (str) {
    return (str ?? '')
      .replace('```html', '')
      .replace('```', '')
      .replace(/<html[^>]*>/g, '') // Removes `<html>` with any attributes
      .replace('</html>', '')
      .replace(/<body[^>]*>/g, '') // Removes `<body>` with any attributes
      .replace('</body>', '')
      .trim();
  }
  return str;
};
