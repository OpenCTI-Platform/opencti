// eslint-disable-next-line import/prefer-default-export
export const getHtmlTextContent = (htmlText: string) => {
  const tmp = document.createElement('DIV');
  tmp.innerHTML = htmlText;
  return tmp.textContent || tmp.innerText || '';
};
