/* eslint-disable */
import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import { ListItem } from '@material-ui/core';
import { withStyles } from '@material-ui/core/styles';
import MenuItem from '@material-ui/core/MenuItem';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import ItemIcon from '../../../../components/ItemIcon';
import { fetchDarklightQuery } from '../../../../relay/environmentDarkLight';

const styles = () => ({
  item: {
    '&.Mui-selected, &.Mui-selected:hover': {
      backgroundColor: '#075AD3',
    },
  },
});

const ResourceTypeComponentQuery = graphql`
 query ResourceTypeComponentQuery {
  componentList {
    edges {
      node {
        name
        description
      }
    }
  }
}
`;
const ResourceTypeInventoryQuery = graphql`
 query ResourceTypeInventoryQuery {
  inventoryItemList {
    edges {
      node {
        name
        description
      }
    }
  }
}
`;
const ResourceTypeResourceQuery = graphql`
 query ResourceTypeResourceQuery {
  oscalResources {
    edges {
      node {
        name
        description
      }
    }
  }
}
`;
const ResourceTypeUserQuery = graphql`
 query ResourceTypeUserQuery {
  oscalUsers {
    edges {
      node {
        name
        description
      }
    }
  }
}
`;
const ResourceTypePartyQuery = graphql`
 query ResourceTypePartyQuery {
  oscalUsers {
    edges {
      node {
        name
        description
      }
    }
  }
}
`;
const ResourceTypeLocationQuery = graphql`
 query ResourceTypeLocationQuery {
  oscalLocations {
    edges {
      node {
        name
        description
      }
    }
  }
}
`;

class ResourceType extends Component {
  constructor(props) {
    super(props);
    this.state = {
      resourceType: {},
      resourceTypeName: '',
      typeList: null,
    };
  }

  componentDidUpdate(prevProps) {
    if (this.props.name !== prevProps.name) {
      this.handleResourceType();
    }
  }

  componentDidMount() {
    this.handleResourceType();
  }

  handleResourceType() {
    this.setState({ typeList: null });
    if (this.props.name === 'component') {
      fetchDarklightQuery(ResourceTypeComponentQuery)
        .toPromise()
        .then((data) => {
          const ResourceTypeEntities = R.pipe(
            R.pathOr([], ['componentList', 'edges']),
            R.map((n) => ({
              name: n.node.name,
              description: n.node.description,
            })),
          )(data);
          this.setState({ resourceType: ResourceTypeEntities });
        });
    }
    if (this.props.name === 'location') {
      fetchDarklightQuery(ResourceTypeLocationQuery)
        .toPromise()
        .then((data) => {
          const ResourceTypeEntities = R.pipe(
            R.pathOr([], ['oscalLocations', 'edges']),
            R.map((n) => ({
              name: n.node.name,
              description: n.node.description,
            })),
          )(data);
          this.setState({ resourceType: ResourceTypeEntities });
        });
    }
    if (this.props.name === 'inventory_item') {
      fetchDarklightQuery(ResourceTypeInventoryQuery)
        .toPromise()
        .then((data) => {
          const ResourceTypeEntities = R.pipe(
            R.pathOr([], ['inventoryItemList', 'edges']),
            R.map((n) => ({
              name: n.node.name,
              description: n.node.description,
            })),
          )(data);
          this.setState({ resourceType: ResourceTypeEntities });
        });
    }
    if (this.props.name === 'party') {
      fetchDarklightQuery(ResourceTypePartyQuery)
        .toPromise()
        .then((data) => {
          const ResourceTypeEntities = R.pipe(
            R.pathOr([], ['oscalParties', 'edges']),
            R.map((n) => ({
              name: n.node.name,
              description: n.node.description,
            })),
          )(data);
          this.setState({ resourceType: ResourceTypeEntities });
        });
    }
    if (this.props.name === 'user') {
      fetchDarklightQuery(ResourceTypeUserQuery)
        .toPromise()
        .then((data) => {
          const ResourceTypeEntities = R.pipe(
            R.pathOr([], ['oscalUsers', 'edges']),
            R.map((n) => ({
              name: n.node.name,
              description: n.node.description,
            })),
          )(data);
          this.setState({ resourceType: ResourceTypeEntities });
        });
    }
    if (this.props.name === 'resource') {
      fetchDarklightQuery(ResourceTypeResourceQuery)
        .toPromise()
        .then((data) => {
          const ResourceTypeEntities = R.pipe(
            R.pathOr([], ['oscalResources', 'edges']),
            R.map((n) => ({
              name: n.node.name,
              description: n.node.description,
            })),
          )(data);
          this.setState({ resourceType: ResourceTypeEntities });
        });
    }
  }

  handleResourceTypeClickEvent(i, resourceName, event) {
    this.setState({ typeList: i, resourceTypeName: resourceName }, () => {
      this.handleResourceRecieveClick();
    });
  }

  handleResourceRecieveClick() {
    this.props.onSelectResource(this.state.resourceTypeName);
  }

  render() {
    const {
      t,
      name,
      classes,
    } = this.props;
    return (
      <>
        {this.state.resourceType.length > 0
          ? this.state.resourceType.map((value, i) => (
            <ListItem
              key={i}
              classes={{ root: classes.item }}
              onClick={this.handleResourceTypeClickEvent.bind(this, i, value.name)}
              selected={this.state.typeList === i}
              button={true}
            >
              {value.name}
            </ListItem>
          ))
          : <></>}
      </>
    );
  }
}

export default R.compose(withStyles(styles), inject18n)(ResourceType);
