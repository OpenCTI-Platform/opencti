import React, { FunctionComponent } from 'react';
import { PreloadedQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import List from '@mui/material/List';
import { NarrativesLines_data$key } from '@components/techniques/narratives/__generated__/NarrativesLines_data.graphql';
import { NarrativesLinesPaginationQuery, NarrativesLinesPaginationQuery$variables } from './__generated__/NarrativesLinesPaginationQuery.graphql';
import { NarrativeLine_node$data } from './__generated__/NarrativeLine_node.graphql';
import { narrativesLinesFragment, narrativesLinesQuery } from './NarrativesLines';
import NarrativeWithSubnarrativeLine, { NarrativeWithSubnarrativeLineDummy } from './NarrativeWithSubnarrativeLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const useStyles = makeStyles(() => ({
  root: {
    marginTop: 30,
  },
}));

export interface SubNarrativeNode {
  description: string | null | undefined;
  id: string;
  name: string;
}
export interface NarrativeNode {
  description: string | null | undefined;
  id: string;
  isSubNarrative: boolean | null | undefined;
  name: string;
  // subNarratives?: { edges: { node: SubNarrativeNode }[] }
  subNarratives?:SubNarrativeNode[];
  subNarrativesText: string;
}

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
  NarrativesLines_data$key
  >({
    linesQuery: narrativesLinesQuery,
    linesFragment: narrativesLinesFragment,
    queryRef,
    nodePath: ['narratives', 'pageInfo', 'globalCount'],
  });

  const filterByKeyword = (n: NarrativeNode) => {
    console.log('filterByKeyword', n);
    return keyword === ''
    || n.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
    || (n.description ?? '').toLowerCase().indexOf(keyword.toLowerCase()) !== -1
    || (n?.subNarrativesText ?? '').toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
  };

  const filterSubNarrativeByKeyword = (n: SubNarrativeNode) => {
    console.log('filterSubNarrativeByKeyword', n);
    return keyword === ''
        || n.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
        || (n.description ?? '').toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
  };

  console.log('data?.narratives?.edges', { plouf: data?.narratives?.edges });

  const narratives = ((data?.narratives?.edges ?? []).map((nnode) => nnode?.node)
    /* .map((n) => ({
      ...n,
      isSubNarrative: n?.isSubNarrative ?? false,
      subNarratives: n?.subNarratives ?? { edges: [] },
      subNarrativesText: ((n?.subNarratives ?? {}).edges ?? []).map((o) => `${o?.node.name} ${o?.node.description}`).join(' | '),
    }))) */
    .map((n) => {
      console.log('Mapping', n);
      const subNarratives: SubNarrativeNode[] = [];
      if (n?.subNarratives?.edges) {
        for (let i = 0; i < n?.subNarratives?.edges?.length; i += 1) {
          subNarratives.push(n?.subNarratives?.edges[i].node as SubNarrativeNode);
        }
      }
      const narrativeNode: NarrativeNode = {
        description: n.description,
        id: n.id,
        name: n.name,
        isSubNarrative: n?.isSubNarrative ?? false,
        subNarrativesText: ((n?.subNarratives ?? {}).edges ?? []).map((o) => `${o?.node.name} ${o?.node.description}`).join(' | '),
        subNarratives,
      };
      console.log('Mapping to', narrativeNode);
      return narrativeNode;
    })
    // .filter((n) => !n.isSubNarrative)
    .filter(filterByKeyword)
    .sort((a, b) => (a?.name ?? '').localeCompare(b?.name ?? '')));

  return (
    <List
      component="nav"
      aria-labelledby="nested-list-subheader"
      className={classes.root}
    >
      {data
        ? narratives.map((narrative) => {
          const subNarratives = ((narrative.subNarratives ?? [])
            // .filter(filterSubNarrativeByKeyword)
            .sort((a, b) => (a?.name ?? '').localeCompare(b?.name ?? '')));
          console.log('RENDER narrative', narrative);
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
