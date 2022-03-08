/* eslint-disable */
import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import { ListItem } from '@material-ui/core';
import MenuItem from '@material-ui/core/MenuItem';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import ItemIcon from '../../../../components/ItemIcon';
import { fetchDarklightQuery } from '../../../../relay/environmentDarkLight';

const ResourceTypeQuery = graphql`
 query ResourceTypeQuery {
  inventoryItemList {
    edges {
      node {
        name
        description
      }
    }
  }
  componentList {
    edges {
      node {
        name
        description
      }
    }
  }
  oscalResources {
    edges {
      node {
        name
        description
      }
    }
  }
  oscalUsers {
    edges {
      node {
        name
        description
      }
    }
  }
  oscalParties {
    edges {
      node {
        name
        description
      }
    }
  }
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
    if (this.props.name === 'Component') {
      fetchDarklightQuery(ResourceTypeQuery)
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
    if (this.props.name === 'Location') {
      fetchDarklightQuery(ResourceTypeQuery)
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
    if (this.props.name === 'Inventory Item') {
      fetchDarklightQuery(ResourceTypeQuery)
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
    if (this.props.name === 'Interview Party') {
      fetchDarklightQuery(ResourceTypeQuery)
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
    if (this.props.name === 'User') {
      fetchDarklightQuery(ResourceTypeQuery)
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
    if (this.props.name === 'Resource or Artifact') {
      fetchDarklightQuery(ResourceTypeQuery)
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

  render() {
    const {
      t,
      name,
    } = this.props;
    return (
      <>
        {this.state.resourceType.length > 0
          ? this.state.resourceType.map((value, i) => (
            <ListItem
              key={i}
              onClick={() => this.setState({ typeList: i })}
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

export default inject18n(ResourceType);
