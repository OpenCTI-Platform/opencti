import useAuth from './useAuth';

interface DraftContext {
  id: string;
  name: string;
  draft_status: string;
  processingCount: number;
}

const useDraftContext = (): DraftContext | null | undefined => {
  const { me } = useAuth();
  return me.draftContext;
};

export default useDraftContext;
