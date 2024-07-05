import React, { FunctionComponent } from 'react';
import { PreloadedQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import List from '@mui/material/List';
import { NarrativesLinesPaginationQuery, NarrativesLinesPaginationQuery$variables } from './__generated__/NarrativesLinesPaginationQuery.graphql';
import { NarrativeLine_node$data } from './__generated__/NarrativeLine_node.graphql';
import { narrativesLinesFragment, narrativesLinesQuery } from './NarrativesLines';
import { NarrativesWithSubnarrativesLines_data$key } from './__generated__/NarrativesWithSubnarrativesLines_data.graphql';
import NarrativeWithSubnarrativeLine, { NarrativeWithSubnarrativeLineDummy } from './NarrativeWithSubnarrativeLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const useStyles = makeStyles(() => ({
  root: {
    marginTop: 30,
  },
}));

interface NarrativesWithSubnarrativesLinesProps {
  queryRef: PreloadedQuery<NarrativesLinesPaginationQuery>;
  paginationOptions: NarrativesLinesPaginationQuery$variables;
  onToggleEntity: (
    entity: NarrativeLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  redirectionMode?: string;
  keyword: string;
}

const NarrativesWithSubnarrativesLines: FunctionComponent<NarrativesWithSubnarrativesLinesProps> = ({
  queryRef,
  keyword,
}) => {
  const classes = useStyles();
  const { data } = usePreloadedPaginationFragment<
  NarrativesLinesPaginationQuery,
  NarrativesWithSubnarrativesLines_data$key
  >({
    linesQuery: narrativesLinesQuery,
    linesFragment: narrativesLinesFragment,
    queryRef,
    nodePath: ['narratives', 'pageInfo', 'globalCount'],
  });

  const filterByKeyword = (n) => keyword === ''
        || n.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
        || (n.description ?? '').toLowerCase().indexOf(keyword.toLowerCase())
        !== -1
        || (n.subnarratives_text ?? '')
          .toLowerCase()
          .indexOf(keyword.toLowerCase()) !== -1;

  const narratives = (data?.narratives?.edges ?? []).map((n) => n?.node)
    .map((n) => ({
      ...n,
      isSubNarrative: n?.isSubNarrative ?? false,
      subNarratives: n?.subNarratives ?? { edges: [] },
      subnarratives_text: ((n?.subNarratives ?? {}).edges ?? []).map((o) => `${o?.node.name} ${o?.node.description}`).join(' | '),
    }))
    .filter((n) => n.isSubNarrative === false)
    .filter(filterByKeyword)
    .sort((a, b) => (a?.name ?? '').localeCompare(b?.name ?? ''));

  return (
    <List
      component="nav"
      aria-labelledby="nested-list-subheader"
      className={classes.root}
    >
      {data
        ? narratives.map((narrative) => {
          const subNarratives = (narrative.subNarratives.edges ?? [])
            .map((n) => n?.node)
            .filter(filterByKeyword)
            .sort((a, b) => (a?.name ?? '').localeCompare(b?.name ?? ''));
          return (
            <NarrativeWithSubnarrativeLine
              key={narrative.id}
              node={narrative}
              subNarratives={subNarratives}
            />
          );
        })
        : Array.from(Array(20), (e, i) => <NarrativeWithSubnarrativeLineDummy key={i} />)}
    </List>
  );
};

export default NarrativesWithSubnarrativesLines;
