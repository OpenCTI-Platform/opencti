import makeStyles from '@mui/styles/makeStyles';
import { graphql, PreloadedQuery, useMutation } from 'react-relay';
import React, { FunctionComponent } from 'react';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { CheckCircle } from '@mui/icons-material';
import { ProgressWrench } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { Theme } from '../../../../components/Theme';
import { truncate } from '../../../../utils/String';
import { deleteNodeFromEdge } from '../../../../utils/store';
import { AddAttackPatternsLinesToDataComponentQuery } from './__generated__/AddAttackPatternsLinesToDataComponentQuery.graphql';
import { DataComponentAttackPatterns_dataComponent$data } from './__generated__/DataComponentAttackPatterns_dataComponent.graphql';
import { AddAttackPatternsLinesToDataComponent_data$key } from './__generated__/AddAttackPatternsLinesToDataComponent_data.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  avatar: {
    width: 24,
    height: 24,
  },
  icon: {
    color: theme.palette.primary.main,
  },
}));

const addAttackPatternsMutationRelationAdd = graphql`
  mutation AddAttackPatternsLinesToDataComponentRelationAddMutation(
    $input: StixCoreRelationshipAddInput
  ) {
    stixCoreRelationshipAdd(input: $input) {
      from {
        ...DataComponentAttackPatterns_dataComponent
      }
    }
  }
`;

export const addAttackPatternsMutationRelationDelete = graphql`
  mutation AddAttackPatternsLinesToDataComponentRelationDeleteMutation(
    $fromId: StixRef!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreRelationshipDelete(
      fromId: $fromId
      toId: $toId
      relationship_type: $relationship_type
    )
  }
`;

export const addAttackPatternsLinesQuery = graphql`
  query AddAttackPatternsLinesToDataComponentQuery(
    $search: String
    $count: Int!
    $cursor: ID
  ) {
    ...AddAttackPatternsLinesToDataComponent_data @arguments(
      search: $search,
      count: $count,
      cursor: $cursor
    )
  }
`;

export const addAttackPatternsLinesFragment = graphql`
  fragment AddAttackPatternsLinesToDataComponent_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
  ) @refetchable(queryName: "AddAttackPatternsLinesRefetchQuery") {
    attackPatterns(
      search: $search,
      first: $count,
      after: $cursor
    )
    @connection(key: "Pagination_attackPatterns") {
      edges {
        node {
          id
          name
          description
        }
      }
    }
  }
`;

interface AddAttackPatternsLinesContainerProps {
  dataComponent: DataComponentAttackPatterns_dataComponent$data,
  queryRef: PreloadedQuery<AddAttackPatternsLinesToDataComponentQuery>,
}

const AddAttackPatternsLines: FunctionComponent<AddAttackPatternsLinesContainerProps> = ({
  dataComponent,
  queryRef,
}) => {
  const classes = useStyles();

  const { data } = usePreloadedPaginationFragment<AddAttackPatternsLinesToDataComponentQuery, AddAttackPatternsLinesToDataComponent_data$key>({
    linesQuery: addAttackPatternsLinesQuery,
    linesFragment: addAttackPatternsLinesFragment,
    queryRef,
    nodePath: ['attackPatterns', 'edges'],
  });

  const [commitAdd] = useMutation(addAttackPatternsMutationRelationAdd);
  const [commitDelete] = useMutation(addAttackPatternsMutationRelationDelete);

  const attackPatterns = dataComponent.attackPatterns?.edges;
  const attackPatternsIds = attackPatterns?.map((attackPattern) => attackPattern?.node.id);

  const toggleAttackPattern = (attackPatternId: string) => {
    const alreadyAdded = attackPatternsIds?.includes(attackPatternId);

    if (!!attackPatterns && alreadyAdded) {
      const existingAttackPattern = attackPatterns.find((attackPattern) => attackPattern?.node.id === attackPatternId);
      if (existingAttackPattern) {
        commitDelete({
          variables: {
            fromId: dataComponent.id,
            toId: existingAttackPattern.node.id,
            relationship_type: 'detects',
          },
          updater: (store) => deleteNodeFromEdge(store, 'attackPatterns', dataComponent.id, existingAttackPattern.node.id),
        });
      } else {
        throw Error('Error while deleting the attack pattern');
      }
    } else {
      commitAdd({
        variables: {
          input: {
            fromId: dataComponent.id,
            toId: attackPatternId,
            relationship_type: 'detects',
          },
        },
      });
    }
  };

  return (
    <List>
      {data?.attackPatterns?.edges.map((attackPatternNode, idx) => {
        const attackPattern = attackPatternNode?.node;
        if (attackPattern === null || attackPattern === undefined) {
          return <ListItemText
            key={idx}
            primary={
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            }
          />;
        }
        const alreadyAdded = attackPatternsIds?.includes(
          attackPattern.id,
        );
        return (
          <ListItem
            key={attackPattern.id}
            classes={{ root: classes.menuItem }}
            divider={true}
            button={true}
            onClick={() => toggleAttackPattern(attackPattern.id)}
          >
            <ListItemIcon>
              {alreadyAdded ? (
                <CheckCircle classes={{ root: classes.icon }} />
              ) : (
                <ProgressWrench />
              )}
            </ListItemIcon>
            <ListItemText
              primary={attackPattern.name}
              secondary={truncate(attackPattern.description, 120)}
            />
          </ListItem>
        );
      })}
    </List>
  );
};

export default AddAttackPatternsLines;
