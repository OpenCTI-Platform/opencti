import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import { graphql, useLazyLoadQuery } from 'react-relay';
import {
  FilterIconButtonContentWithRedirectionQuery,
} from './__generated__/FilterIconButtonContentWithRedirectionQuery.graphql';

export const filterIconButtonContentWithRedirectionQuery = graphql`
    query FilterIconButtonContentWithRedirectionQuery(
        $id: String!
    ) {
        stixObjectOrStixRelationship(id: $id) {
            ... on StixCoreObject {
                id
            }
        }
    }
`;

interface FilterIconButtonContentWithRedirectionProps {
  filterId: string,
  displayedValue: string,
}

const FilterIconButtonContentWithRedirection: FunctionComponent<FilterIconButtonContentWithRedirectionProps> = ({
  filterId,
  displayedValue,
}) => {
  const instanceData = useLazyLoadQuery<FilterIconButtonContentWithRedirectionQuery>(
    filterIconButtonContentWithRedirectionQuery,
    { id: filterId },
  );
  const entityId = instanceData.stixObjectOrStixRelationship?.id;

  return (
    <span>
      {entityId
        ? <Link to={`/dashboard/id/${filterId}`}>
          <span color="primary">
            {displayedValue}{' '}
          </span>
        </Link>
        : <del>{displayedValue}{' '}</del>
      }
    </span>
  );
};

export default FilterIconButtonContentWithRedirection;
