import { useEffect, useState } from 'react';
import { fetchQuery } from '../../../../../relay/environment';
import { fetchPlaybooks } from '../enrollPlaybookDrawer.utils';
import type { Playbook, FetchPlaybooksParams } from '../enrollPlaybookDrawer.utils';

export interface UseEnrollPlaybooksParams extends FetchPlaybooksParams {
  open: boolean;
}

const fetcher = (query: unknown, variables: Record<string, unknown>) => {
  return fetchQuery(query, variables).toPromise() as Promise<unknown>;
};

const useEnrollPlaybooks = ({ open, ...params }: UseEnrollPlaybooksParams) => {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open) return;
    setLoading(true);
    setPlaybooks([]);
    fetchPlaybooks(params, fetcher).then((result) => {
      setPlaybooks(result);
      setLoading(false);
    });
  }, [open]);

  return { playbooks, loading };
};

export default useEnrollPlaybooks;
