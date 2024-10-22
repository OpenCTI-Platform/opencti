import { useContext } from 'react';
import { UserContext, UserContextType } from './useAuth';

const setDocumentTitle = (title: string) => {
  document.title = title;
};

const useConnectedDocumentModifier = () => {
  const { settings } = useContext<UserContextType>(UserContext);
  const setTitle = (title: string) => {
    setDocumentTitle(`${title}${!settings ? '' : ` | ${settings.platform_title}`}`);
  };
  return { setTitle };
};

export default useConnectedDocumentModifier;
