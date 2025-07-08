import { graphql, useFragment } from 'react-relay';
import React from 'react';
import PirKnowledgeRelationships from '@components/pir/pir_knowledge/PirKnowledgeRelationships';
import { PirKnowledgeFragment$key } from './__generated__/PirKnowledgeFragment.graphql';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { PaginationOptions } from '../../../../components/list_lines';

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
    sortBy: 'pir_score',
    orderAsc: false,
    openExports: false,
    view: 'relationships',
  };

  const localStorage = usePaginationLocalStorage<PaginationOptions>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  // const viewButtons = [
  //   <ToggleButton key="relationships" value="relationships" aria-label="relationships">
  //     <Tooltip title={t_i18n('Relationships view')}>
  //       <RelationManyToMany
  //         fontSize="small"
  //         color={viewStorage.view === 'relationships' ? 'secondary' : 'primary'}
  //       />
  //     </Tooltip>
  //   </ToggleButton>,
  //   <ToggleButton key="entities" value="entities" aria-label="entities">
  //     <Tooltip title={t_i18n('Entities view')}>
  //       <LibraryBooksOutlined
  //         fontSize="small"
  //         color={viewStorage.view === 'entities' ? 'secondary' : 'primary'}
  //       />
  //     </Tooltip>
  //   </ToggleButton>,
  // ];

  return (
    <div>
      <PirKnowledgeRelationships
        pirId={pir.id}
        localStorage={localStorage}
        initialValues={initialValues}
      />
    </div>
  );
};

export default PirKnowledge;
