import React from 'react';
import TextField from '@mui/material/TextField';
import { graphql } from 'react-relay';

const savedFilterFragment = graphql`
  query SavedFiltersInputQuery {
    savedFilters {
      edges {
        node {
          id
          standard_id
          entity_type
          parent_types
          name
          filters
          scope
        }
      }
    }
  }
`;
console.log('SAVED FILTER', savedFilterFragment);
const SavedFiltersInput = () => {
  return (
    <>
      <TextField
        variant="outlined"
        size="small"
        label={'Saved filters'}
      />
    </>
  );
};
export default SavedFiltersInput;
