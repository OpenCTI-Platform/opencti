import React from 'react';
import DataTableWithoutFragment from '../../components/dataGrid/DataTableWithoutFragment';

interface SearchBulkUnknownEntitiesProps {
  values: string[],
}

const SearchBulkUnknownEntities = ({ values }: SearchBulkUnknownEntitiesProps) => {
  // TODO: query to known which values have no match
  const unknownEntities = values.map((value) => ({
    id: value.trim(),
    type: 'Unknown',
    value: value.trim(),
  }));
  const dataColumns = {
    entity_type: {},
    value: {},
  };
  return (
    <DataTableWithoutFragment
      data={unknownEntities}
      globalCount={unknownEntities.length}
      dataColumns={dataColumns}
      storageKey={'searchBulk_unknownEntities'}
    />
  );
};

export default SearchBulkUnknownEntities;
