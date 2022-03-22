/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import MenuItem from '@material-ui/core/MenuItem';
import Tooltip from '@material-ui/core/Tooltip';
import { Information } from 'mdi-material-ui';
import graphql from 'babel-plugin-relay/macro'
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { fetchDarklightQuery } from '../../../../relay/environmentDarkLight';

const RelatedResponseQuery = graphql`
 query RelatedResponseQuery{
  __type(name: "RiskResponse") {
    name
    description
    fields {
      name
      description
    }
  }
}
`;

class RelatedResponse extends Component {
  constructor(props) {
    super(props);
    this.state = {
      relatedResponseList: [],
    }
  }
  componentDidMount() {
    fetchDarklightQuery(RelatedResponseQuery)
      .toPromise()
      .then((data) => {
        const relatedResponseEntities = R.pipe(
          R.pathOr([], ['__type', 'fields']),
          R.map((n) => ({
            label: n.description,
            value: n.name,
          })),
        )(data);
        this.setState({
          relatedResponseList: {
            ...this.state.entities,
            relatedResponseEntities
          },
        });
      })
  }

  render() {
    const {
      t,
      name,
      size,
      label,
      style,
      variant,
      onChange,
      onFocus,
      containerstyle,
      editContext,
      disabled,
      helperText,
    } = this.props;
    const relatedResponseList = R.pathOr(
      [],
      ['relatedResponseEntities'],
      this.state.relatedResponseList,
    );
    console.log('relatedData', relatedResponseList)
    return (
      <div>
        <div className="clearfix" />
        <Field
          component={SelectField}
          name={name}
          label={label}
          fullWidth={true}
          containerstyle={containerstyle}
          variant={variant}
          disabled={disabled || false}
          size={size}
          style={style}
          helperText={helperText}
        >
          {relatedResponseList.map((resp, key) => (
            resp.label
            && <Tooltip
              title={resp.label}
              value={resp.value}
              key={resp.label}
            >
              <MenuItem value={resp.value}>
                {resp.value}
              </MenuItem>
            </Tooltip>
          ))}
        </Field>
      </div>
    );
  }
}

export default inject18n(RelatedResponse);
