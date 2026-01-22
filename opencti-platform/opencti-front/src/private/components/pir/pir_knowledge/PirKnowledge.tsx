/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { graphql, useFragment } from 'react-relay';
import React from 'react';
import PirKnowledgeEntities from '@components/pir/pir_knowledge/PirKnowledgeEntities';
import { PirKnowledgeFragment$key } from './__generated__/PirKnowledgeFragment.graphql';
import { emptyFilterGroup, useGetDefaultFilterObject } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { PaginationOptions } from '../../../../components/list_lines';

const knowledgeFragment = graphql`
  fragment PirKnowledgeFragment on Pir {
    id
  }
`;

interface PirKnowledgeProps {
  data: PirKnowledgeFragment$key;
}

const PirKnowledge = ({ data }: PirKnowledgeProps) => {
  const pir = useFragment(knowledgeFragment, data);
  const pirId = pir.id;
  const LOCAL_STORAGE_KEY = `Pir-SourcesFlaggedList-${pirId}`;

  const initialValues = {
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['pir_score', 'last_pir_score_date'], ['Stix-Domain-Object']),
    },
    searchTerm: '',
    sortBy: 'pir_score',
    orderAsc: false,
    openExports: false,
  };

  const localStorage = usePaginationLocalStorage<PaginationOptions>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  return (
    <div>
      <PirKnowledgeEntities
        pirId={pirId}
        localStorage={localStorage}
        initialValues={initialValues}
        additionalHeaderButtons={[]}
      />
    </div>
  );
};

export default PirKnowledge;
