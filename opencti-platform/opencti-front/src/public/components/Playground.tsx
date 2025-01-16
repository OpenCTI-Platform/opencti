import React from 'react';
import { GraphiQL } from 'graphiql';
import { createGraphiQLFetcher } from '@graphiql/toolkit';
import 'graphiql/graphiql.css';
import Box from '@mui/material/Box';
import { APP_BASE_PATH } from '../../relay/environment';
import { useFormatter } from '../../components/i18n';
import PublicTopBar from './PublicTopBar';

const defaultQuery = `query ExampleQuery {
  intrusionSets {
    edges {
      node {
        id
        name
        standard_id
        created_at
        objectLabel {
          value
        }
      }
    }
  }
}`;

const placeholder = `
# Welcome to the OpenCTI GraphQL Playground
#
# Write queries and mutations here, you will get auto-complete hints as you type. 
# You can provide your query variables in the panel below, 
# or browse the schema with the documentation explorer on the left.
#
# Keyboard shortcuts:
#
#   Prettify query:  Shift-Ctrl-P (or press the prettify button)
#
#  Merge fragments:  Shift-Ctrl-M (or press the merge button)
#
#        Run Query:  Ctrl-Enter (or press the play button)
#
#    Auto Complete:  Ctrl-Space (or just start typing)
#
#
# An example GraphQL query might look like:
#
${defaultQuery}
`;

const exampleWithVariables = `
  query filteredIntrusionSets($first: Int, $filters: FilterGroup) {
    intrusionSets(first: $first, filters: $filters, orderBy: name) {
      edges {
        node {
          id
          name
          standard_id
          created_at
          objectLabel {
            value
          }
        }
      }
    }
  }`;

const exampleVariables = {
  first: 5,
  filters: {
    mode: 'or',
    filters: [
      {
        key: 'created_at',
        operator: 'gt',
        values: '2024-01-01T00:00:00.000Z',
      },
    ],
    filterGroups: [],
  },
};

const fetcher = createGraphiQLFetcher({ url: `${APP_BASE_PATH}/graphql` });

const Playground: React.FC = () => {
  const { t_i18n } = useFormatter();
  return (
    <Box
      sx={{
        height: '100vh',
        display: 'flex',
        flexDirection: 'column',
        pre: {
          backgroundColor: 'transparent !important',
        },
      }}
    >
      <PublicTopBar title={t_i18n('GraphQL playground')} />
      <GraphiQL
        fetcher={fetcher}
        defaultTabs={[
          { query: placeholder },
          { query: exampleWithVariables, variables: JSON.stringify(exampleVariables, null, '  ') },
        ]}
        forcedTheme={'dark'}
      />
    </Box>
  );
};

export default Playground;
