import React, { Component } from 'react';
import {
  compose, pathOr, pipe, map,
} from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { CenterFocusStrong } from '@mui/icons-material';
import { Field } from 'formik';
import graphql from 'babel-plugin-relay/macro';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
});

export const groupsQuery = graphql`
  query GroupFieldQuery {
    groups {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

class GroupField extends Component {
  constructor(props) {
    super(props);
    this.state = { groups: [] };
  }

  searchGroups() {
    fetchQuery(groupsQuery)
      .toPromise()
      .then((data) => {
        const groups = pipe(
          pathOr([], ['groups', 'edges']),
          map((n) => ({
            label: n.node.name,
            value: n.node.id,
          })),
        )(data);
        this.setState({ groups });
      });
  }

  render() {
    const {
      t, name, style, classes, onChange, helpertext, disabled,
    } = this.props;
    return (
      <Field
        component={AutocompleteField}
        style={style}
        name={name}
        multiple={true}
        disabled={disabled}
        textfieldprops={{
          label: t('Groups'),
          helperText: helpertext,
          onFocus: this.searchGroups.bind(this),
        }}
        noOptionsText={t('No available options')}
        options={this.state.groups}
        onInputChange={this.searchGroups.bind(this)}
        onChange={typeof onChange === 'function' ? onChange.bind(this) : null}
        renderOption={(option) => (
          <React.Fragment>
            <div className={classes.icon} style={{ color: option.color }}>
              <CenterFocusStrong />
            </div>
            <div className={classes.text}>{option.label}</div>
          </React.Fragment>
        )}
      />
    );
  }
}

export default compose(inject18n, withStyles(styles))(GroupField);
