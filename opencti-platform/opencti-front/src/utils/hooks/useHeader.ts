const setTitle = (title: string) => {
  document.title = title;
};

const setLang = (lang: string) => {
  document.documentElement.lang = lang;
};

const useHeader = () => {
  return { setTitle, setLang };
};

export default useHeader;
