import { graphql, useFragment } from 'react-relay';
import React from 'react';
import PirKnowledgeEntities from '@components/pir/PirKnowledgeEntities';
import PirKnowledgeRelationships from '@components/pir/PirKnowledgeRelationships';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { LibraryBooksOutlined } from '@mui/icons-material';
import { RelationManyToMany } from 'mdi-material-ui';
import { PirKnowledgeFragment$key } from './__generated__/PirKnowledgeFragment.graphql';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { PaginationOptions } from '../../../components/list_lines';
import { useFormatter } from '../../../components/i18n';

const knowledgeFragment = graphql`
  fragment PirKnowledgeFragment on Pir {
    id
  }
`;

interface PirKnowledgeProps {
  data: PirKnowledgeFragment$key
}

const PirKnowledge = ({ data }: PirKnowledgeProps) => {
  const { t_i18n } = useFormatter();
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

  const viewButtons = [
    (<ToggleButton key="entities" value="entities" aria-label="entities">
      <Tooltip title={t_i18n('Entities view')}>
        <LibraryBooksOutlined fontSize="small" color="secondary" />
      </Tooltip>
    </ToggleButton>),
    (<ToggleButton key="relationships" value="relationships" aria-label="relationships">
      <Tooltip title={t_i18n('Relationships view')}>
        <RelationManyToMany color="primary" fontSize="small" />
      </Tooltip>
    </ToggleButton>),
  ];

  return (
    <div>
      {viewStorage.view === 'entities'
        ? <PirKnowledgeEntities
            pirId={pir.id}
            localStorage={localStorage}
            initialValues={initialValues}
            additionalHeaderButtons={viewButtons}
          />
        : <PirKnowledgeRelationships
            pirId={pir.id}
            localStorage={localStorage}
            initialValues={initialValues}
            additionalHeaderButtons={viewButtons}
          />
      }
    </div>
  );
};

export default PirKnowledge;
