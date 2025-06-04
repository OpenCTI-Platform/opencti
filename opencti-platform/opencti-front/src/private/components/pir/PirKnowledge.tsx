import { graphql, useFragment } from 'react-relay';
import React from 'react';
import PirKnowledgeEntities from '@components/pir/PirKnowledgeEntities';
import PirKnowledgeRelationships from '@components/pir/PirKnowledgeRelationships';
import { PirKnowledgeFragment$key } from './__generated__/PirKnowledgeFragment.graphql';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { PaginationOptions } from '../../../components/list_lines';

const knowledgeFragment = graphql`
  fragment PirKnowledgeFragment on Pir {
    id
  }
`;

interface PirKnowledgeProps {
  data: PirKnowledgeFragment$key
}

const PirKnowledge = ({ data }: PirKnowledgeProps) => {
  const pir = useFragment(knowledgeFragment, data);
  const LOCAL_STORAGE_KEY = `PirSourcesFlaggedList-${pir.id}`;

  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'created',
    orderAsc: true,
    openExports: false,
    view: 'relationships',
  };

  const localStorage = usePaginationLocalStorage<PaginationOptions>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const { viewStorage } = localStorage;

  return (
    <div>
      {viewStorage.view === 'entities'
        ? <PirKnowledgeEntities
            pirId={pir.id}
            localStorage={localStorage}
            initialValues={initialValues}
          />
        : <PirKnowledgeRelationships
            pirId={pir.id}
            localStorage={localStorage}
            initialValues={initialValues}
          />
      }
    </div>
  );
};

export default PirKnowledge;
