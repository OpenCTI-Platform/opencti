import React, { Component } from 'react';
import * as R from 'ramda';
import { Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import MenuItem from '@material-ui/core/MenuItem';
import graphql from 'babel-plugin-relay/macro';
import Tooltip from '@material-ui/core/Tooltip';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { fetchDarklightQuery } from '../../../../relay/environmentDarkLight';

const styles = (theme) => ({
  chip: {
    margin: '0 7px 7px 0',
    color: theme.palette.header.text,
    backgroundColor: theme.palette.header.background,
  },
  importButton: {
    position: 'absolute',
    top: 30,
    right: 30,
  },
  deleteIcon: {
    color: theme.palette.header.text,
  },
});

const SourceActorTypeQuery = graphql`
  query SourceActorTypeQuery {
    __type(name: "ActorType") {
      name
      description
      enumValues {
        name
        description
      }
    }
  }
`;

const componentFilter = [];

componentFilter.push({ key: 'asset_type', values: 'software' });

const ComponentListQuery = graphql`
  query SourceComponentListQuery{
    componentList(filters: [
    {
      key: component_type,
      values: "software"
    }
    ]){
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

const AssessmentPlatformQuery = graphql`
  query SourceAssessmentPlatformQuery {
    assessmentPlatforms {
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

const OscalPartiesQuery = graphql`
  query SourceOscalPartiesQuery {
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
class Source extends Component {
  constructor(props) {
    super(props);
    this.state = {
      actorTypeList: [],
      oscalPartiesList: [],
      actorReferences: [],
      selectedWeakCount: null,
      actor_type: null,
    };
  }

  componentDidMount() {
    fetchDarklightQuery(SourceActorTypeQuery)
      .toPromise()
      .then((data) => {
        const actorTypeEntities = R.pipe(
          R.pathOr([], ['__type', 'enumValues']),
          R.map((n) => ({
            label: n.description,
            value: n.name,
          })),
        )(data);
        this.setState({
          actorTypeList: {
            ...this.state.entities,
            actorTypeEntities,
          },
        });
      });
  }

  render() {
    const {
      size,
      label,
      style,
      variant,
      containerstyle,
      disabled,
      helperText,
    } = this.props;

    const handleThisChange = (name, value) => {
      let queryType;
      let queryInfo;
      let filterBy = '';

      if (value) {
        switch (value) {
          case 'tool':
            queryType = ComponentListQuery;
            queryInfo = 'componentList';
            filterBy = {
              filters: [
                {
                  key: 'component_type',
                  values: 'software',
                },
              ],
            };
            break;
          case 'assessment_platform':
            queryType = AssessmentPlatformQuery;
            queryInfo = 'assessmentPlatforms';
            break;
          case 'party':
            queryType = OscalPartiesQuery;
            queryInfo = 'oscalParties';
            break;
          default:
          //
        }
        fetchDarklightQuery(queryType)
          .toPromise()
          .then((data) => {
            const oscalEntities = R.pipe(
              R.pathOr({}, [queryInfo, 'edges']),
              R.map((n) => ({
                key: n.node.id,
                label: n.node.name,
                value: n.node.id,
              })),
            )(data);

            this.setState({
              actorReferences: {
                ...this.state.entities,
                oscalEntities,
              },
            });
          });
      }
    };
    const actorTypeList = R.pathOr(
      [],
      ['actorTypeEntities'],
      this.state.actorTypeList,
    );

    const actorReferences = R.pathOr(
      [],
      ['oscalEntities'],
      this.state.actorReferences,
    );

    return (
      <div>
        <div className='clearfix' />
        <Field
          component={SelectField}
          name='actor_type'
          onChange={handleThisChange.bind(this)}
          label={label}
          fullWidth={true}
          containerstyle={containerstyle}
          variant={variant}
          disabled={disabled || false}
          size={size}
          style={style}
          helperText={helperText}
        >
          <MenuItem></MenuItem>
          {actorTypeList.map(
            (et) => et.label && (
              <Tooltip title={et.label} value={et.value} key={et.label}>
                <MenuItem value={et.value}>{et.value}
               </MenuItem>
              </Tooltip>
            ),
          )}
        </Field>
        <Field
          component={SelectField}
          name='actor_ref'
          label={label}
          fullWidth={true}
          containerstyle={containerstyle}
          variant={variant}
          disabled={disabled || false}
          size={size}
          style={style}
          helperText={helperText}
        >
           <MenuItem></MenuItem>
          {actorReferences?.map(
            (et) => (
             <MenuItem key={et.key} value={et.key}>{et.label}</MenuItem>
            ),
          )}
        </Field>
      </div>
    );
  }
}
export default R.compose(inject18n, withStyles(styles))(Source);
