import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import MenuItem from '@material-ui/core/MenuItem';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { fetchQuery } from '../../../../relay/environment';

const dataUsageRestrictionFieldQuery = graphql`
  query DataUsageRestrictionFieldQuery($filters: [DataMarkingFiltering] $orderMode: OrderingMode, $orderedBy: DataMarkingOrdering) {
    dataMarkings(
      orderedBy: $orderedBy 
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          __typename
          ... on IEPMarking {
            id
            iep_version
            name
            description
            start_date
            end_date
            encrypt_in_transit
            permitted_actions
            affected_party_notifications
            attribution
            unmodified_resale
          }
        }
      }
    }
  }
`;

class DataUsageRestrictionField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      list: [],
    };
  }

  componentDidMount() {
    fetchQuery(dataUsageRestrictionFieldQuery, {
      filters: [
        {
          key: 'definition_type',
          values: 'iep',
        },
      ],
      orderMode: 'asc',
      orderedBy: 'name',
    })
      .toPromise()
      .then((data) => {
        const dataMarkings = R.pipe(
          R.pathOr([], ['dataMarkings', 'edges']),
          R.map((n) => ({
            id: n.node.id,
            name: n.node.name,
          })),
        )(data);
        this.setState({
          list: [
            ...this.state.list,
            ...dataMarkings,
          ],
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
      multiple,
      containerstyle,
      disabled,
      helperText,
    } = this.props;
    return (
      <div>
        <div className="clearfix" />
        <Field
          component={SelectField}
          name={name}
          label={label}
          fullWidth={true}
          multiple={multiple}
          containerstyle={containerstyle}
          variant={variant}
          disabled={disabled || false}
          size={size}
          style={style}
          helperText={helperText}
        >
          {this.state.list.map((item, key) => (
            item.id
            && <MenuItem key={key} value={item.id}>
              {t(item.name)}
            </MenuItem>
          ))}
        </Field>
      </div>
    );
  }
}

export default inject18n(DataUsageRestrictionField);
