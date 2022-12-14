import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import MenuItem from '@material-ui/core/MenuItem';
import { withStyles } from '@material-ui/core/styles';
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
    '&.Mui-selected, &.Mui-selected:hover, &.Mui-selected:focus': {
      backgroundColor: '#075AD3',
    },
  },
});
const ResourceTypeFieldQuery = graphql`
 query ResourceTypeFieldQuery{
  __type(name: "SubjectType" ) {
    name
    enumValues {
      description
      name
    }
  }
}
`;

class ResourceTypeField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      resourceTypeList: [],
      resourceTypeName: '',
    };
  }

  componentDidMount() {
    fetchQuery(ResourceTypeFieldQuery)
      .toPromise()
      .then((data) => {
        const resourceTypeEntities = R.pipe(
          R.pathOr([], ['__type', 'enumValues']),
          R.map((n) => ({
            name: n.name,
            description: n.description,
          })),
        )(data);
        this.setState({
          resourceTypeList: {
            ...this.state.entities,
            resourceTypeEntities,
          },
        });
      });
  }

  render() {
    const {
      t,
      name,
      size,
      label,
      style,
      variant,
      classes,
      handleResourceType,
      containerstyle,
      disabled,
      helperText,
    } = this.props;
    const resourceTypeList = R.pathOr(
      [],
      ['resourceTypeEntities'],
      this.state.resourceTypeList,
    );
    return (
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
        multiple={false}
        containerstyle={containerstyle}
        variant={variant}
        disabled={disabled || false}
        size={size}
        style={style}
        helperText={helperText}
      >
          <MenuItem value={''}>
            <em>None</em>
          </MenuItem>
        {resourceTypeList.map((resourceType, key) => (
          resourceType.name
          && <MenuItem
            onClick={() => this.setState({ resourceTypeName: resourceType.name },
              () => handleResourceType(this.state.resourceTypeName))}
            key={key}
            classes={{ root: classes.menuItemRoot }}
            value={resourceType.name}
          >
            {t(resourceType.description)}
          </MenuItem>
        ))}
      </Field>
    );
  }
}

export default R.compose(
  inject18n,
  withStyles(styles),
)(ResourceTypeField);
