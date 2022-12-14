import makeStyles from '@mui/styles/makeStyles';
import { graphql, PreloadedQuery, useMutation } from 'react-relay';
import React, { FunctionComponent } from 'react';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { CheckCircle, SourceOutlined } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { Theme } from '../../../../components/Theme';
import { truncate } from '../../../../utils/String';
import { AddDataComponentsLinesQuery } from './__generated__/AddDataComponentsLinesQuery.graphql';
import { AddDataComponentsLines_data$key } from './__generated__/AddDataComponentsLines_data.graphql';
import { deleteNodeFromEdge } from '../../../../utils/store';
import { AttackPatternDataComponents_attackPattern$data } from './__generated__/AttackPatternDataComponents_attackPattern.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  avatar: {
    width: 24,
    height: 24,
  },
  icon: {
    color: theme.palette.primary.main,
  },
}));

const addDataComponentsMutationRelationAdd = graphql`
  mutation AddDataComponentsLinesRelationAddMutation(
    $input: StixCoreRelationshipAddInput
  ) {
    stixCoreRelationshipAdd(input: $input) {
      to {
        ...AttackPatternDataComponents_attackPattern
      }
    }
  }
`;

export const addDataComponentsMutationRelationDelete = graphql`
  mutation AddDataComponentsLinesRelationDeleteMutation(
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

export const addDataComponentsLinesQuery = graphql`
  query AddDataComponentsLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
  ) {
    ...AddDataComponentsLines_data @arguments(
      search: $search,
      count: $count,
      cursor: $cursor
    )
  }
`;

export const addDataComponentsLinesFragment = graphql`
  fragment AddDataComponentsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
  ) @refetchable(queryName: "AddDataComponentsLinesRefetchQuery") {
    dataComponents(
      search: $search,
      first: $count,
      after: $cursor
    )
    @connection(key: "Pagination_dataComponents") {
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

interface AddDataComponentsLinesContainerProps {
  attackPattern: AttackPatternDataComponents_attackPattern$data,
  queryRef: PreloadedQuery<AddDataComponentsLinesQuery>,
}

const AddDataComponentsLines: FunctionComponent<AddDataComponentsLinesContainerProps> = ({
  attackPattern,
  queryRef,
}) => {
  const classes = useStyles();

  const { data } = usePreloadedPaginationFragment<AddDataComponentsLinesQuery, AddDataComponentsLines_data$key>({
    linesQuery: addDataComponentsLinesQuery,
    linesFragment: addDataComponentsLinesFragment,
    queryRef,
  });

  const [commitAdd] = useMutation(addDataComponentsMutationRelationAdd);
  const [commitDelete] = useMutation(addDataComponentsMutationRelationDelete);

  const dataComponents = attackPattern.dataComponents?.edges;
  const dataComponentsIds = dataComponents?.map((dataComponent) => dataComponent?.node.id);

  const toggleDataComponent = (dataComponentId: string) => {
    const alreadyAdded = dataComponentsIds?.includes(dataComponentId);

    if (!!dataComponents && alreadyAdded) {
      const existingDataComponent = dataComponents.find((dataComponent) => dataComponent?.node.id === dataComponentId);
      if (existingDataComponent) {
        commitDelete({
          variables: {
            fromId: existingDataComponent.node.id,
            toId: attackPattern.id,
            relationship_type: 'detects',
          },
          updater: (store) => deleteNodeFromEdge(store, 'dataComponents', attackPattern.id, existingDataComponent.node.id),
        });
      } else {
        throw Error('Error while deleting the data component');
      }
    } else {
      commitAdd({
        variables: {
          input: {
            fromId: dataComponentId,
            toId: attackPattern.id,
            relationship_type: 'detects',
          },
        },
      });
    }
  };

  return (
    <List>
      {data?.dataComponents?.edges?.map((dataComponentNode, idx) => {
        const dataComponent = dataComponentNode?.node;
        if (dataComponent === null || dataComponent === undefined) {
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
        const alreadyAdded = dataComponentsIds?.includes(
          dataComponent.id,
        );
        return (
          <ListItem
            key={dataComponent.id}
            classes={{ root: classes.menuItem }}
            divider={true}
            button={true}
            onClick={() => toggleDataComponent(dataComponent.id)}
          >
            <ListItemIcon>
              {alreadyAdded ? (
                <CheckCircle classes={{ root: classes.icon }} />
              ) : (
                <SourceOutlined />
              )}
            </ListItemIcon>
            <ListItemText
              primary={dataComponent.name}
              secondary={truncate(dataComponent.description, 120)}
            />
          </ListItem>
        );
      })}
    </List>
  );
};

export default AddDataComponentsLines;
