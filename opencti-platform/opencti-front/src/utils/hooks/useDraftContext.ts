import useAuth from './useAuth';

export interface DraftContext {
  id: string;
  name: string;
  draft_status: string;
  processingCount: number;
  currentUserAccessRight: string | null | undefined;
}

const useDraftContext = (): DraftContext | null | undefined => {
  const { me } = useAuth();
  return me.draftContext;
};

export default useDraftContext;
