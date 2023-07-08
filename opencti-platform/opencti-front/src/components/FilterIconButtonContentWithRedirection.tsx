import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { FilterIconButtonContentWithRedirectionQuery } from './__generated__/FilterIconButtonContentWithRedirectionQuery.graphql';
import useQueryLoading from '../utils/hooks/useQueryLoading';

export const filterIconButtonContentWithRedirectionQuery = graphql`
  query FilterIconButtonContentWithRedirectionQuery($id: String!) {
    stixObjectOrStixRelationship(id: $id) {
      ... on BasicObject {
        id
      }
      ... on BasicRelationship {
        id
      }
    }
  }
`;

interface FilterIconButtonContentWithRedirectionComponentProps {
  queryRef: PreloadedQuery<FilterIconButtonContentWithRedirectionQuery>;
  displayedValue: string;
}

interface FilterIconButtonContentWithRedirectionProps {
  filterId: string;
  displayedValue: string;
}

const FilterIconButtonContentWithRedirectionComponent: FunctionComponent<
FilterIconButtonContentWithRedirectionComponentProps
> = ({ queryRef, displayedValue }) => {
  const data = usePreloadedQuery<FilterIconButtonContentWithRedirectionQuery>(
    filterIconButtonContentWithRedirectionQuery,
    queryRef,
  );
  return (
    <>
      {data.stixObjectOrStixRelationship?.id ? (
        <Link to={`/dashboard/id/${data.stixObjectOrStixRelationship.id}`}>
          <span color="primary">{displayedValue}</span>
        </Link>
      ) : (
        <del>{displayedValue}</del>
      )}
    </>
  );
};

const FilterIconButtonContentWithRedirection: FunctionComponent<
FilterIconButtonContentWithRedirectionProps
> = ({ filterId, displayedValue }) => {
  const queryRef = useQueryLoading<FilterIconButtonContentWithRedirectionQuery>(
    filterIconButtonContentWithRedirectionQuery,
    { id: filterId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<span color="disabled">{displayedValue}</span>}
        >
          <FilterIconButtonContentWithRedirectionComponent
            queryRef={queryRef}
            displayedValue={displayedValue}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default FilterIconButtonContentWithRedirection;
