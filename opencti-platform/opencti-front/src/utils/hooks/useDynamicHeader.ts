const setTitle = (title: string) => {
  document.title = title;
};

const setLang = (lang: string) => {
  document.documentElement.lang = lang;
};

const useDynamicHeader = () => {
  return { setTitle, setLang };
};

export default useDynamicHeader;
