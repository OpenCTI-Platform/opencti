import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';

const useStyles = makeStyles(() => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
}));

const PlaybookAddComponentsConfig = ({ data, onSelect, componentId }) => {
  const classes = useStyles();
  const { playbookComponents } = data;
  const selectedComponent = playbookComponents.filter((n) => n.id === componentId).at(0);
  return (
    <List>
      {playbookComponents.map((playbookComponent) => {
        return (
          <ListItem
            key={playbookComponent.id}
            divider={true}
            button={true}
            clases={{ root: classes.item }}
            onClick={() => onSelect(playbookComponent)}
          >
            <ListItemText
              primary={playbookComponent.name}
              secondary={playbookComponent.description}
            />
          </ListItem>
        );
      })}
    </List>
  );
};

export const playbookAddComponentsConfigQuery = graphql`
  query PlaybookAddComponentsConfigQuery {
    ...PlaybookAddComponentsConfig_data
  }
`;

const PlaybookAddComponentsConfigFragment = createFragmentContainer(
  PlaybookAddComponentsConfig,
  {
    data: graphql`
      fragment PlaybookAddComponentsConfig_data on Query {
        playbookComponents {
          id
          name
          description
          is_entry_point
          is_internal
          configuration_schema
          ports {
            id
            type
          }
        }
      }
    `,
  },
);

export default PlaybookAddComponentsConfigFragment;
