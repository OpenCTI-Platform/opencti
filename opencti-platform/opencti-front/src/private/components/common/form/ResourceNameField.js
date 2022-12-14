import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import MenuItem from '@material-ui/core/MenuItem';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { fetchQuery } from '../../../../relay/environment';

const styles = () => ({
  resourceTypeField: {
    backgroundColor: '#06102D',
    maxHeight: 130,
  },
  menuItemRoot: {
    '&.Mui-selected, &.Mui-selected:hover': {
      backgroundColor: '#075AD3',
    },
  },
});

const ResourceNameFieldComponentQuery = graphql`
 query ResourceNameFieldComponentQuery {
  componentList {
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
const ResourceNameFieldInventoryQuery = graphql`
 query ResourceNameFieldInventoryQuery {
  inventoryItemList {
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
const ResourceNameFieldResourceQuery = graphql`
 query ResourceNameFieldResourceQuery {
  oscalResources {
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
const ResourceNameFieldUserQuery = graphql`
 query ResourceNameFieldUserQuery {
  oscalUsers {
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
const ResourceNameFieldPartyQuery = graphql`
 query ResourceNameFieldPartyQuery {
  oscalParties {
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
const ResourceNameFieldLocationQuery = graphql`
 query ResourceNameFieldLocationQuery {
  oscalLocations {
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

class ResourceNameField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      resourceType: [],
      resourceTypeName: '',
      typeList: null,
    };
  }

  componentDidUpdate(prevProps) {
    if (this.props.resourceTypename !== prevProps.resourceTypename) {
      this.handleResourceType();
    }
  }

  componentDidMount() {
    this.handleResourceType();
  }

  handleResourceType() {
    this.setState({ typeList: null });
    if (this.props.resourceTypename === 'component') {
      fetchQuery(ResourceNameFieldComponentQuery)
        .toPromise()
        .then((data) => {
          const ResourceTypeEntities = R.pipe(
            R.pathOr([], ['componentList', 'edges']),
            R.map((n) => ({
              id: n.node.id,
              name: n.node.name,
              description: n.node.description,
            })),
          )(data);
          this.setState({ resourceType: ResourceTypeEntities });
        });
    }
    if (this.props.resourceTypename === 'location') {
      fetchQuery(ResourceNameFieldLocationQuery)
        .toPromise()
        .then((data) => {
          const ResourceTypeEntities = R.pipe(
            R.pathOr([], ['oscalLocations', 'edges']),
            R.map((n) => ({
              id: n.node.id,
              name: n.node.name,
              description: n.node.description,
            })),
          )(data);
          this.setState({ resourceType: ResourceTypeEntities });
        });
    }
    if (this.props.resourceTypename === 'inventory_item') {
      fetchQuery(ResourceNameFieldInventoryQuery)
        .toPromise()
        .then((data) => {
          const ResourceTypeEntities = R.pipe(
            R.pathOr([], ['inventoryItemList', 'edges']),
            R.map((n) => ({
              id: n.node.id,
              name: n.node.name,
              description: n.node.description,
            })),
          )(data);
          this.setState({ resourceType: ResourceTypeEntities });
        });
    }
    if (this.props.resourceTypename === 'party') {
      fetchQuery(ResourceNameFieldPartyQuery)
        .toPromise()
        .then((data) => {
          const ResourceTypeEntities = R.pipe(
            R.pathOr([], ['oscalParties', 'edges']),
            R.map((n) => ({
              id: n.node.id,
              name: n.node.name,
              description: n.node.description,
            })),
          )(data);
          this.setState({ resourceType: ResourceTypeEntities });
        });
    }
    if (this.props.resourceTypename === 'user') {
      fetchQuery(ResourceNameFieldUserQuery)
        .toPromise()
        .then((data) => {
          const ResourceTypeEntities = R.pipe(
            R.pathOr([], ['oscalUsers', 'edges']),
            R.map((n) => ({
              id: n.node.id,
              name: n.node.name,
              description: n.node.description,
            })),
          )(data);
          this.setState({ resourceType: ResourceTypeEntities });
        });
    }
    if (this.props.resourceTypename === 'resource') {
      fetchQuery(ResourceNameFieldResourceQuery)
        .toPromise()
        .then((data) => {
          const ResourceTypeEntities = R.pipe(
            R.pathOr([], ['oscalResources', 'edges']),
            R.map((n) => ({
              id: n.node.id,
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
      name,
      classes,
      size,
      label,
      style,
      variant,
      containerstyle,
      disabled,
      helperText,
    } = this.props;
    return (
      <>
        <Field
          component={SelectField}
          name={name}
          MenuProps={{
            anchorOrigin: {
              vertical: 'bottom',
              horizontal: 'left',
            },
            getContentAnchorEl: null,
            classes: { paper: classes.resourceTypeField },
          }}
          label={label}
          fullWidth={true}
          containerstyle={containerstyle}
          variant={variant}
          disabled={disabled || false}
          size={size}
          multiple={false}
          style={style}
          helperText={helperText}
        >
          <MenuItem value={''}>
            <em>None</em>
          </MenuItem>
          {this.state.resourceType.map((value, i) => (
            <MenuItem
              key={i}
              classes={{ root: classes.menuItemRoot }}
              value={value.id}
            >
              {value.name}
            </MenuItem>
          ))}
        </Field>
      </>
    );
  }
}

export default R.compose(withStyles(styles), inject18n)(ResourceNameField);
