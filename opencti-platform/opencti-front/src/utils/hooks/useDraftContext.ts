import useAuth from './useAuth';

interface DraftContext {
  id: string;
  name: string;
}

const useDraftContext = (): DraftContext | null | undefined => {
  const { me } = useAuth();
  return me.draftContext;
};

export default useDraftContext;
