import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useMutation } from 'react-relay';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import { CheckCircle, SourceOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { truncate } from '../../../../utils/String';
import type { Theme } from '../../../../components/Theme';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { DataSourceDataComponents_dataSource$data } from './__generated__/DataSourceDataComponents_dataSource.graphql';
import { AddDataComponentsLinesToDataSourceQuery } from './__generated__/AddDataComponentsLinesToDataSourceQuery.graphql';
import { AddDataComponentsLinesToDataSource_data$key } from './__generated__/AddDataComponentsLinesToDataSource_data.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  icon: {
    color: theme.palette.primary.main,
  },
}));

const addDataComponentsMutationRelationAdd = graphql`
  mutation AddDataComponentsLinesToDataSourceRelationAddMutation(
    $id: ID!
    $dataComponentId: ID!
  ) {
    dataSourceDataComponentAdd(id: $id, dataComponentId: $dataComponentId) {
      ...DataSourceDataComponents_dataSource
    }
  }
`;

export const addDataComponentsMutationRelationDelete = graphql`
  mutation AddDataComponentsLinesToDataSourceRelationDeleteMutation(
    $id: ID!
    $dataComponentId: ID!
  ) {
    dataSourceDataComponentDelete(id: $id, dataComponentId: $dataComponentId) {
      ...DataSourceDataComponents_dataSource
    }
  }
`;

export const addDataComponentsLinesQuery = graphql`
  query AddDataComponentsLinesToDataSourceQuery(
    $search: String
    $count: Int
    $cursor: ID
  ) {
    ...AddDataComponentsLinesToDataSource_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

export const addDataComponentsLinesFragment = graphql`
  fragment AddDataComponentsLinesToDataSource_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
  )
  @refetchable(queryName: "AddDataComponentsLinesToDataSourceRefetchQuery") {
    dataComponents(search: $search, first: $count, after: $cursor)
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
  dataSource: DataSourceDataComponents_dataSource$data;
  queryRef: PreloadedQuery<AddDataComponentsLinesToDataSourceQuery>;
}

const AddDataComponentsLines: FunctionComponent<
AddDataComponentsLinesContainerProps
> = ({ dataSource, queryRef }) => {
  const classes = useStyles();
  const { data } = usePreloadedPaginationFragment<
  AddDataComponentsLinesToDataSourceQuery,
  AddDataComponentsLinesToDataSource_data$key
  >({
    linesQuery: addDataComponentsLinesQuery,
    linesFragment: addDataComponentsLinesFragment,
    queryRef,
    nodePath: ['dataComponents', 'pageInfo', 'globalCount'],
  });

  const [commitAdd] = useMutation(addDataComponentsMutationRelationAdd);
  const [commitDelete] = useMutation(addDataComponentsMutationRelationDelete);

  const dataComponents = dataSource.dataComponents?.edges;
  const dataComponentsIds = dataComponents?.map(
    (dataComponent) => dataComponent?.node.id,
  );

  const toggleDataComponent = (dataComponentId: string) => {
    const alreadyAdded = dataComponentsIds?.includes(dataComponentId);

    if (!!dataComponents && alreadyAdded) {
      const existingDataComponent = dataComponents.find(
        (dataComponent) => dataComponent?.node.id === dataComponentId,
      );
      if (existingDataComponent) {
        commitDelete({
          variables: {
            id: dataSource.id,
            dataComponentId,
          },
        });
      } else {
        throw Error('Error while deleting the data component');
      }
    } else {
      commitAdd({
        variables: {
          id: dataSource.id,
          dataComponentId,
        },
      });
    }
  };

  return (
    <List>
      {data?.dataComponents?.edges?.map((dataComponentNode, idx) => {
        const dataComponent = dataComponentNode?.node;
        if (dataComponent === null || dataComponent === undefined) {
          return (
            <ListItemText
              key={idx}
              primary={
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              }
            />
          );
        }
        const alreadyAdded = dataComponentsIds?.includes(dataComponent.id);
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
