import React, { FunctionComponent } from 'react';
import { PreloadedQuery } from 'react-relay';
import List from '@mui/material/List';
import { NarrativesLines_data$key } from '@components/techniques/narratives/__generated__/NarrativesLines_data.graphql';
import * as R from 'ramda';
import { NarrativesLinesPaginationQuery } from './__generated__/NarrativesLinesPaginationQuery.graphql';
import { narrativesLinesFragment, narrativesLinesQuery } from './NarrativesLines';
import NarrativeWithSubnarrativeLine, { NarrativeWithSubnarrativeLineDummy } from './NarrativeWithSubnarrativeLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

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
}

const NarrativesWithSubnarrativesLines: FunctionComponent<NarrativesWithSubnarrativesLinesProps> = ({
  queryRef,
}) => {
  const { data } = usePreloadedPaginationFragment<
  NarrativesLinesPaginationQuery,
  NarrativesLines_data$key
  >({
    linesQuery: narrativesLinesQuery,
    linesFragment: narrativesLinesFragment,
    queryRef,
    nodePath: ['narratives', 'pageInfo', 'globalCount'],
  });

  const allNarratives = ((data?.narratives?.edges ?? []).map((nnode) => nnode?.node));

  const narratives = allNarratives.filter((n) => !n.isSubNarrative);

  const subNarrativesOnly = allNarratives
    .filter((n) => n.isSubNarrative)
    .filter((n) => n.parentNarratives)
    .filter(({ parentNarratives }) => (parentNarratives?.edges ?? []).some(({ node }) => !narratives.some(({ id }) => id === node.id)));

  const parentOnlyNarratives = R.uniq(subNarrativesOnly.flatMap(({ parentNarratives }) => parentNarratives?.edges?.map(({ node }) => node)));

  return (
    <List
      component="nav"
      aria-labelledby="nested-list-subheader"
    >
      {data
        ? ([...narratives, ...parentOnlyNarratives] as unknown as SubNarrativeNode[]).map((narrative) => {
          return (
            <NarrativeWithSubnarrativeLine
              key={narrative.id}
              node={narrative}
            />
          );
        })
        : Array.from(Array(20), (e, i) => <NarrativeWithSubnarrativeLineDummy key={i} />)}
    </List>
  );
};

export default NarrativesWithSubnarrativesLines;
