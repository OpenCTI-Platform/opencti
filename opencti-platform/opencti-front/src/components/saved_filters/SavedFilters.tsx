import React from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { SavedFiltersQuery } from 'src/components/saved_filters/__generated__/SavedFiltersQuery.graphql';
import SavedFilterSelection from './SavedFilterSelection';

const savedFiltersQuery = graphql`
  query SavedFiltersQuery {
    savedFilters(first: 100) @connection(key: "SavedFilters__savedFilters") {
      edges {
        node {
          id
          name
          filters
          scope
        }
      }
    }
  }
`;

type SavedFiltersComponentProps = {
  queryRef: PreloadedQuery<SavedFiltersQuery>;
};

const SavedFiltersComponent = ({ queryRef }: SavedFiltersComponentProps) => {
  const { savedFilters } = usePreloadedQuery(savedFiltersQuery, queryRef);

  return (
    <>
      <SavedFilterSelection
        isDisabled={!savedFilters?.edges.length}
        data={savedFilters?.edges.map(({ node }) => node) ?? []}
      />
    </>
  );
};

const SavedFilters = () => {
  const queryRef = useQueryLoading<SavedFiltersQuery>(savedFiltersQuery);

  return (
    <>
      {queryRef && (
        <SavedFiltersComponent queryRef={queryRef} />
      )}
    </>
  );
};

export default SavedFilters;
