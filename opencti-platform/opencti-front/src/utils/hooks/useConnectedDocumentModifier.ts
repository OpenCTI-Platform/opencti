import useAuth from './useAuth';

const setDocumentTitle = (title: string) => {
  document.title = title;
};

const useConnectedDocumentModifier = () => {
  const { settings } = useAuth();
  const setTitle = (title: string) => {
    setDocumentTitle(`${title} | ${settings.platform_title}`);
  };
  return { setTitle };
};

export default useConnectedDocumentModifier;
