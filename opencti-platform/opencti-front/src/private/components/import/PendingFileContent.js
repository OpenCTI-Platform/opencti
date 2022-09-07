import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import Axios from 'axios';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import List from '@mui/material/List';
import { v4 as uuid } from 'uuid';
import Typography from '@mui/material/Typography';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import { graphql, createFragmentContainer } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import MenuItem from '@mui/material/MenuItem';
import DialogActions from '@mui/material/DialogActions';
import Checkbox from '@mui/material/Checkbox';
import * as Yup from 'yup';
import { Link, withRouter } from 'react-router-dom';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import { CodeJson } from 'mdi-material-ui';
import { Cell, Pie, PieChart, ResponsiveContainer } from 'recharts';
import withTheme from '@mui/styles/withTheme';
import Select from '@mui/material/Select';
import IconButton from '@mui/material/IconButton';
import ItemIcon from '../../../components/ItemIcon';
import { defaultValue } from '../../../utils/Graph';
import inject18n from '../../../components/i18n';
import {
  getObservablePatternMapping,
  observableKeyToType,
  resolveLink,
} from '../../../utils/Entity';
import PendingFileToolBar from './PendingFileToolBar';
import {
  commitMutation,
  fetchQuery,
  MESSAGING$,
} from '../../../relay/environment';
import { fileManagerAskJobImportMutation } from '../common/files/FileManager';
import SelectField from '../../../components/SelectField';
import { convertStixType } from '../../../utils/String';
import { itemColor } from '../../../utils/Colors';
import ItemBoolean from '../../../components/ItemBoolean';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  paperList: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemNested: {
    paddingLeft: 30,
    height: 50,
  },
  gridContainer: {
    marginBottom: 20,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  linesContainer: {
    marginTop: 0,
  },
  itemHead: {
    paddingLeft: 10,
    textTransform: 'uppercase',
    cursor: 'pointer',
  },
  bodyItem: {
    height: '100%',
    fontSize: 13,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  inputLabel: {
    float: 'left',
  },
  sortIcon: {
    float: 'left',
    margin: '-5px 0 0 15px',
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

const inlineStylesHeaders = {
  iconSort: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
    top: '0px',
  },
  type: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  default_value: {
    float: 'left',
    width: '40%',
    fontSize: 12,
    fontWeight: '700',
  },
  in_platform: {
    float: 'left',
    width: '8%',
    fontSize: 12,
    fontWeight: '700',
  },
  nb_dependencies: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
  },
  nb_inbound_dependencies: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
  },
  created: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
};

const inlineStyles = {
  type: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  default_value: {
    float: 'left',
    width: '40%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  in_platform: {
    float: 'left',
    width: '8%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  nb_dependencies: {
    float: 'left',
    width: '10%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  nb_inbound_dependencies: {
    float: 'left',
    width: '10%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  created: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

const pendingFileContentUploadMutation = graphql`
  mutation PendingFileContentUploadMutation($file: Upload!, $entityId: String) {
    uploadPending(file: $file, entityId: $entityId) {
      ...FileLine_file
    }
  }
`;

const pendingFileContentDeleteMutation = graphql`
  mutation PendingFileContentDeleteMutation($fileName: String) {
    deleteImport(fileName: $fileName)
  }
`;

const importValidation = (t) => Yup.object().shape({
  connector_id: Yup.string().required(t('This field is required')),
});

const pendingFileContentResolveEntitiesQuery = graphql`
  query PendingFileContentResolveEntitiesQuery(
    $first: Int
    $filters: [StixCoreObjectsFiltering]
  ) {
    stixCoreObjects(first: $first, filters: $filters) {
      edges {
        node {
          id
          standard_id
          entity_type
          parent_types
          created_at
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            edges {
              node {
                id
                definition
              }
            }
          }
          ... on StixDomainObject {
            created
          }
          ... on AttackPattern {
            name
            description
            x_mitre_id
          }
          ... on Campaign {
            name
            description
            first_seen
            last_seen
          }
          ... on Note {
            attribute_abstract
          }
          ... on ObservedData {
            name
            first_observed
            last_observed
          }
          ... on Opinion {
            opinion
          }
          ... on Report {
            name
            description
            published
          }
          ... on CourseOfAction {
            name
            description
          }
          ... on Individual {
            name
            description
          }
          ... on Organization {
            name
            description
          }
          ... on Sector {
            name
            description
          }
          ... on System {
            name
            description
          }
          ... on Indicator {
            name
            description
            valid_from
          }
          ... on Infrastructure {
            name
            description
          }
          ... on IntrusionSet {
            name
            description
            first_seen
            last_seen
          }
          ... on Position {
            name
            description
          }
          ... on City {
            name
            description
          }
          ... on Country {
            name
            description
          }
          ... on Region {
            name
            description
          }
          ... on Malware {
            name
            description
            first_seen
            last_seen
          }
          ... on ThreatActor {
            name
            description
            first_seen
            last_seen
          }
          ... on Tool {
            name
            description
          }
          ... on Vulnerability {
            name
            description
          }
          ... on Incident {
            name
            description
            first_seen
            last_seen
          }
          ... on StixCyberObservable {
            observable_value
            x_opencti_description
          }
        }
      }
    }
  }
`;

class PendingFileContentComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      allObjectsIds: [],
      allContainers: {},
      checkedObjects: [],
      containersChecked: {},
      containersUnchecked: {},
      uncheckedObjects: [],
      resolvedObjects: {},
      objects: [],
      indexedObjects: {},
      objectsWithDependencies: [],
      indexedObjectsWithDependencies: {},
      dataToValidate: null,
      sortBy: 'nb_inbound_dependencies',
      orderAsc: false,
      checkAll: true,
      currentJson: '',
      displayJson: false,
    };
  }

  handleOpenValidate() {
    const data = R.pipe(
      R.map((n) => this.state.indexedObjects[n]),
      R.map((n) => {
        if (n.object_refs) {
          return R.assoc('object_refs', this.state.containersChecked[n.id], n);
        }
        return n;
      }),
    )(this.state.checkedObjects);
    this.setState({ dataToValidate: data });
  }

  handleCloseValidate() {
    this.setState({ dataToValidate: null });
  }

  handleOpenJson(content) {
    this.setState({ displayJson: true, currentJson: content });
  }

  handleCloseJson() {
    this.setState({ displayJson: false, currentJson: '' });
  }

  onSubmitValidate(values, { setSubmitting, resetForm }) {
    const objects = this.state.dataToValidate;
    const data = { id: `bundle--${uuid()}`, type: 'bundle', objects };
    const json = JSON.stringify(data);
    const blob = new Blob([json], { type: 'text/json' });
    const file = new File([blob], this.props.file.name, {
      type: 'application/json',
    });
    commitMutation({
      mutation: pendingFileContentUploadMutation,
      variables: {
        file,
        entityId: this.props.file.metaData.entity
          ? this.props.file.metaData.entity.id
          : null,
      },
      onCompleted: () => {
        setTimeout(() => {
          commitMutation({
            mutation: fileManagerAskJobImportMutation,
            variables: {
              fileName: this.props.file.id,
              connectorId: values.connector_id,
              bypassValidation: true,
            },
            onCompleted: () => {
              setSubmitting(false);
              resetForm();
              this.handleCloseValidate();
              MESSAGING$.notifySuccess('Import successfully asked');
              if (this.props.file.metaData.entity) {
                const entityLink = `${resolveLink(
                  this.props.file.metaData.entity.entity_type,
                )}/${this.props.file.metaData.entity.id}`;
                this.props.history.push(`${entityLink}/files`);
              } else {
                this.props.history.push('/dashboard/import');
              }
            },
          });
        }, 2000);
      },
    });
  }

  handleDrop() {
    const { file } = this.props;
    commitMutation({
      mutation: pendingFileContentDeleteMutation,
      variables: { fileName: file.id },
      onCompleted: () => {
        if (this.props.file.metaData.entity) {
          const entityLink = `${resolveLink(
            this.props.file.metaData.entity.entity_type,
          )}/${this.props.file.metaData.entity.id}`;
          this.props.history.push(`${entityLink}/files`);
        } else {
          this.props.history.push('/dashboard/import');
        }
      },
    });
  }

  loadFileContent() {
    const { file } = this.props;
    const url = `/storage/view/${encodeURIComponent(file.id)}`;
    Axios.get(url).then(async (res) => {
      const state = await this.computeState(res.data.objects);
      this.setState(state);
      return true;
    });
  }

  componentDidMount() {
    this.loadFileContent();
  }

  // eslint-disable-next-line class-methods-use-this
  async computeState(objects) {
    const indexedObjects = R.indexBy(R.prop('id'), objects);
    const allObjectsIds = R.map((n) => n.id, objects);
    const dependencies = {};
    for (const object of objects) {
      let objectDependencies = [];
      for (const [key, value] of Object.entries(object)) {
        if (key.endsWith('_refs')) {
          objectDependencies = [...objectDependencies, ...value];
        } else if (key.endsWith('_ref')) {
          const isCreatedByRef = key === 'created_by_ref';
          if (isCreatedByRef) {
            if (!object.id.startsWith('marking-definition--')) {
              objectDependencies = R.append(value, objectDependencies);
            }
          } else {
            objectDependencies = R.append(value, objectDependencies);
          }
        }
      }
      dependencies[object.id] = {
        id: object.id,
        dependencies: objectDependencies,
      };
    }
    let objectsWithDependencies = [];
    const containersChecked = {};
    for (const object of objects) {
      if (object.object_refs) {
        containersChecked[object.id] = object.object_refs;
      }
      const inboundDependencies = R.map(
        (n) => n.id,
        R.filter(
          (o) => o.dependencies.includes(object.id)
            && !o.id.startsWith('report')
            && !o.id.startsWith('opinion')
            && !o.id.startsWith('note'),
          R.values(dependencies),
        ),
      );
      const objectWithDependencies = R.pipe(
        R.assoc(
          'default_value',
          defaultValue(
            R.pipe(
              R.assoc(
                'source_ref_name',
                object.source_ref
                  ? defaultValue(indexedObjects[object.source_ref] || {})
                  : null,
              ),
              R.assoc(
                'target_ref_name',
                object.target_ref
                  ? defaultValue(indexedObjects[object.target_ref] || {})
                  : null,
              ),
            )(object),
          ),
        ),
        R.assoc('dependencies', dependencies[object.id].dependencies),
        R.assoc('nb_dependencies', dependencies[object.id].dependencies.length),
        R.assoc('inbound_dependencies', inboundDependencies),
        R.assoc('nb_inbound_dependencies', inboundDependencies.length),
      )(object);
      // eslint-disable-next-line max-len
      objectWithDependencies.nb_inbound_dependencies = objectWithDependencies.inbound_dependencies.length;
      objectsWithDependencies = R.append(
        objectWithDependencies,
        objectsWithDependencies,
      );
    }
    const indexedObjectsWithDependencies = R.indexBy(
      R.prop('id'),
      objectsWithDependencies,
    );
    const refsToResolve = [];
    for (const object of objectsWithDependencies) {
      if (object.object_refs) {
        refsToResolve.push(...object.object_refs);
      }
    }
    const resolvedObjects = {};
    if (refsToResolve.length > 0) {
      await fetchQuery(pendingFileContentResolveEntitiesQuery, {
        first: 1000,
        filters: [{ key: 'standard_id', values: refsToResolve }],
      })
        .toPromise()
        .then(async (data) => {
          if (data.stixCoreObjects && data.stixCoreObjects.edges) {
            for (const edge of data.stixCoreObjects.edges) {
              resolvedObjects[edge.node.standard_id] = R.pipe(
                R.assoc('type', edge.node.entity_type),
                R.assoc('id', edge.node.standard_id),
                R.assoc(
                  'default_value',
                  defaultValue(
                    R.pipe(
                      R.assoc(
                        'source_ref_name',
                        edge.node.source_ref
                          ? defaultValue(
                            indexedObjects[edge.node.source_ref] || {},
                          )
                          : null,
                      ),
                      R.assoc(
                        'target_ref_name',
                        edge.node.target_ref
                          ? defaultValue(
                            indexedObjects[edge.node.target_ref] || {},
                          )
                          : null,
                      ),
                    )(edge.node),
                  ),
                ),
              )(edge.node);
            }
          }
        });
    }
    return {
      allObjectsIds,
      checkedObjects: allObjectsIds,
      objects,
      indexedObjects,
      objectsWithDependencies,
      indexedObjectsWithDependencies,
      containersChecked,
      allContainers: containersChecked,
      resolvedObjects,
    };
  }

  handleToggleItem(itemId) {
    let { uncheckedObjects, containersChecked } = this.state;
    let checkedObjects;
    const { allContainers, containersUnchecked } = this.state;
    const item = this.state.indexedObjectsWithDependencies[itemId];
    if (this.state.checkedObjects.includes(itemId)) {
      uncheckedObjects = R.append(itemId, this.state.uncheckedObjects);
      checkedObjects = R.filter(
        (n) => n !== itemId && !item.inbound_dependencies.includes(n),
        this.state.checkedObjects,
      );
      if (item.object_refs) {
        containersChecked = R.assoc(itemId, [], this.state.containersChecked);
      }
      containersChecked = R.pipe(
        R.toPairs,
        R.map((n) => [n[0], R.filter((o) => o !== itemId, n[1])]),
        R.fromPairs,
      )(containersChecked);
    } else {
      uncheckedObjects = R.filter(
        (n) => n !== itemId,
        this.state.uncheckedObjects,
      );
      checkedObjects = R.append(itemId, this.state.checkedObjects);
      checkedObjects = [
        ...checkedObjects,
        ...R.filter(
          (n) => item.inbound_dependencies.includes(n)
            && !uncheckedObjects.includes(n),
          this.state.allObjectsIds,
        ),
      ];
      if (item.object_refs) {
        containersChecked = R.assoc(
          itemId,
          R.filter(
            (n) => !(containersUnchecked[item.id] || []).includes(n)
              && !this.state.uncheckedObjects.includes(n),
            item.object_refs,
          ),
          this.state.containersChecked,
        );
      }
      containersChecked = R.pipe(
        R.toPairs,
        R.map((n) => [
          n[0],
          !uncheckedObjects.includes(n[0])
          && !(containersUnchecked[n[0]] || []).includes(item.id)
          && allContainers[n[0]].includes(item.id)
            ? R.append(item.id, n[1])
            : n[1],
        ]),
        R.fromPairs,
      )(containersChecked);
    }
    this.setState({ checkedObjects, uncheckedObjects, containersChecked });
  }

  handleToggleContainerItem(containerId, itemId) {
    if (this.state.containersChecked[containerId].includes(itemId)) {
      this.setState({
        containersChecked: R.assoc(
          containerId,
          R.filter(
            (n) => n !== itemId,
            this.state.containersChecked[containerId] || [],
          ),
          this.state.containersChecked,
        ),
        containersUnchecked: R.assoc(
          containerId,
          R.append(itemId, this.state.containersUnchecked[containerId] || []),
          this.state.containersUnchecked,
        ),
      });
    } else {
      this.setState({
        containersChecked: R.assoc(
          containerId,
          R.append(itemId, this.state.containersChecked[containerId] || []),
          this.state.containersChecked,
        ),
        containersUnchecked: R.assoc(
          containerId,
          R.filter(
            (n) => n !== itemId,
            this.state.containersUnchecked[containerId] || [],
          ),
          this.state.containersUnchecked,
        ),
      });
    }
  }

  handleToggleAll() {
    if (this.state.checkAll) {
      this.setState({
        checkedObjects: [],
        containersChecked: {},
        containersUnchecked: this.state.allContainers,
        uncheckedObjects: R.map((n) => n.id, this.state.objects),
        checkAll: false,
      });
    } else {
      this.setState({
        checkedObjects: R.map((n) => n.id, this.state.objects),
        containersChecked: this.state.allContainers,
        containersUnchecked: {},
        uncheckedObjects: [],
        checkAll: true,
      });
    }
  }

  handleChangeType(objectId, event) {
    const originalObject = this.state.indexedObjects[objectId];
    const originalObjectWithDependencies = this.state.indexedObjectsWithDependencies[objectId];
    if (originalObject.type !== 'x-opencti-simple-observable') {
      const newObject = R.assoc('type', event.target.value, originalObject);
      const newObjectWithDependencies = R.assoc(
        'type',
        event.target.value,
        originalObjectWithDependencies,
      );
      const indexedObjects = R.assoc(
        objectId,
        newObject,
        this.state.indexedObjects,
      );
      const indexedObjectsWithDependencies = R.assoc(
        objectId,
        newObjectWithDependencies,
        this.state.indexedObjectsWithDependencies,
      );
      const objectsWithDependencies = R.map((n) => {
        if (n.id === objectId) {
          return newObjectWithDependencies;
        }
        return n;
      }, this.state.objectsWithDependencies);
      this.setState({
        indexedObjects,
        indexedObjectsWithDependencies,
        objectsWithDependencies,
      });
    } else {
      const newObject = R.assoc(
        'key',
        getObservablePatternMapping(event.target.value),
        originalObject,
      );
      const newObjectWithDependencies = R.assoc(
        'key',
        getObservablePatternMapping(event.target.value),
        originalObjectWithDependencies,
      );
      const indexedObjects = R.assoc(
        objectId,
        newObject,
        this.state.indexedObjects,
      );
      const indexedObjectsWithDependencies = R.assoc(
        objectId,
        newObjectWithDependencies,
        this.state.indexedObjectsWithDependencies,
      );
      const objectsWithDependencies = R.map((n) => {
        if (n.id === objectId) {
          return newObjectWithDependencies;
        }
        return n;
      }, this.state.objectsWithDependencies);
      this.setState({
        indexedObjects,
        indexedObjectsWithDependencies,
        objectsWithDependencies,
      });
    }
  }

  reverseBy(field) {
    this.setState({ sortBy: field, orderAsc: !this.state.orderAsc });
  }

  SortHeader(field, label, isSortable) {
    const { t } = this.props;
    const sortComponent = this.state.orderAsc ? (
      <ArrowDropDown style={inlineStylesHeaders.iconSort} />
    ) : (
      <ArrowDropUp style={inlineStylesHeaders.iconSort} />
    );
    if (isSortable) {
      return (
        <div
          style={inlineStylesHeaders[field]}
          onClick={this.reverseBy.bind(this, field)}
        >
          <span>{t(label)}</span>
          {this.state.sortBy === field ? sortComponent : ''}
        </div>
      );
    }
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t(label)}</span>
      </div>
    );
  }

  renderLabel(props) {
    const { theme } = this.props;
    const RADIAN = Math.PI / 180;
    const { cx, cy, midAngle, outerRadius, fill, payload, percent, value } = props;
    const sin = Math.sin(-RADIAN * midAngle);
    const cos = Math.cos(-RADIAN * midAngle);
    const sx = cx + (outerRadius + 10) * cos;
    const sy = cy + (outerRadius + 10) * sin;
    const mx = cx + (outerRadius + 30) * cos;
    const my = cy + (outerRadius + 30) * sin;
    const ex = mx + (cos >= 0 ? 1 : -1) * 22;
    const ey = my;
    const textAnchor = cos >= 0 ? 'start' : 'end';
    return (
      <g>
        <path
          d={`M${sx},${sy}L${mx},${my}L${ex},${ey}`}
          stroke={fill}
          fill="none"
        />
        <circle cx={ex} cy={ey} r={2} fill={fill} stroke="none" />
        <text
          x={ex + (cos >= 0 ? 1 : -1) * 12}
          y={ey}
          textAnchor={textAnchor}
          fill={theme.palette.text.primary}
          style={{ fontSize: 12 }}
        >
          {' '}
          {payload.label} ({value})
        </text>
        <text
          x={ex + (cos >= 0 ? 1 : -1) * 12}
          y={ey}
          dy={18}
          textAnchor={textAnchor}
          fill="#999999"
          style={{ fontSize: 12 }}
        >
          {` ${(percent * 100).toFixed(2)}%`}
        </text>
      </g>
    );
  }

  render() {
    const {
      classes,
      t,
      file,
      fldt,
      connectorsImport,
      nsdt,
      theme,
      stixDomainObjectTypes,
      observableTypes,
    } = this.props;
    const {
      objectsWithDependencies,
      indexedObjectsWithDependencies,
      objects,
      indexedObjects,
      checkedObjects,
      uncheckedObjects,
      dataToValidate,
      checkAll,
      displayJson,
      currentJson,
      containersChecked,
      containersUnchecked,
      resolvedObjects,
    } = this.state;
    const sdoTypes = [
      ...stixDomainObjectTypes.edges.map((n) => n.node.id),
      'Marking-Definition',
      'Identity',
      'Location',
    ];
    const scoTypes = observableTypes.edges.map((n) => n.node.id);
    let entityId = null;
    let entityLink = null;
    if (file.metaData.entity) {
      entityId = file.metaData.entity.standard_id;
      entityLink = `${resolveLink(file.metaData.entity.entity_type)}/${
        file.metaData.entity.id
      }`;
    }
    const sort = R.sortWith(
      this.state.orderAsc
        ? [R.ascend(R.prop(this.state.sortBy))]
        : [R.descend(R.prop(this.state.sortBy))],
    );
    const sortedObjectsWithDependencies = sort(objectsWithDependencies);
    const numberOfEntities = R.filter(
      (n) => n.type !== 'relationship',
      objects,
    ).length;
    const numberOfRelationships = R.filter(
      (n) => n.type === 'relationship',
      objects,
    ).length;
    const graphData = R.pipe(
      R.countBy(R.prop('type')),
      R.toPairs,
      R.map((n) => ({ label: n[0], value: n[1] })),
    )(objects);
    const connectors = R.filter(
      (n) => n.connector_scope.length > 0
        && R.includes('application/json', n.connector_scope),
      connectorsImport,
    );
    return (
      <div className={classes.container}>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {t('Data import')}
        </Typography>
        <div className="clearfix" />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6}>
            <div style={{ height: '100%' }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('File information')}
              </Typography>
              <Paper classes={{ root: classes.paper }} variant="outlined">
                <Grid container={true} spacing={3}>
                  <Grid item={true} xs={12}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Name')}
                    </Typography>
                    <pre style={{ marginBottom: 0 }}>{file.name}</pre>
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Mime-Type')}
                    </Typography>
                    <pre>{file.metaData.mimetype}</pre>
                    <Typography
                      variant="h3"
                      gutterBottom={true}
                      style={{ marginTop: 20 }}
                    >
                      {t('Last modified')}
                    </Typography>
                    {fldt(file.lastModified)}
                    <Typography
                      variant="h3"
                      gutterBottom={true}
                      style={{ marginTop: 20 }}
                    >
                      {t('Number of entities')}
                    </Typography>
                    <span style={{ fontSize: 20 }}>{numberOfEntities}</span>
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Encoding')}
                    </Typography>
                    <pre>{file.metaData.encoding}</pre>
                    <Typography
                      variant="h3"
                      gutterBottom={true}
                      style={{ marginTop: 20 }}
                    >
                      {t('Linked entity')}
                    </Typography>
                    {file.metaData.entity ? (
                      <Button
                        variant="outlined"
                        color="secondary"
                        component={Link}
                        to={entityLink}
                        startIcon={
                          <ItemIcon type={file.metaData.entity.entity_type} />
                        }
                      >
                        {defaultValue(file.metaData.entity)}
                      </Button>
                    ) : (
                      t('None')
                    )}
                    <Typography
                      variant="h3"
                      gutterBottom={true}
                      style={{ marginTop: 20 }}
                    >
                      {t('Number of relationships')}
                    </Typography>
                    <span style={{ fontSize: 20 }}>
                      {numberOfRelationships}
                    </span>
                  </Grid>
                </Grid>
              </Paper>
            </div>
          </Grid>
          <Grid item={true} xs={6}>
            <div style={{ height: '100%' }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Bundle details')}
              </Typography>
              <Paper classes={{ root: classes.paper }} variant="outlined">
                <div style={{ height: 300 }}>
                  <ResponsiveContainer height="100%" width="100%">
                    <PieChart
                      margin={{
                        top: 40,
                        right: 0,
                        bottom: 30,
                        left: 0,
                      }}
                    >
                      <Pie
                        data={graphData}
                        dataKey="value"
                        nameKey="label"
                        cx="50%"
                        cy="50%"
                        fill="#82ca9d"
                        innerRadius="63%"
                        outerRadius="80%"
                        label={this.renderLabel.bind(this)}
                        labelLine={true}
                        paddingAngle={5}
                      >
                        {graphData.map((entry, index) => (
                          <Cell
                            key={index}
                            fill={itemColor(entry.label)}
                            stroke={theme.palette.background.paper}
                          />
                        ))}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </Paper>
            </div>
          </Grid>
        </Grid>
        <Typography variant="h4" gutterBottom={true} style={{ marginTop: 50 }}>
          {t('Bundle content')}
        </Typography>
        <Paper classes={{ root: classes.paperList }} variant="outlined">
          <List classes={{ root: classes.linesContainer }}>
            <ListItem
              classes={{ root: classes.itemHead }}
              divider={false}
              style={{ paddingTop: 0 }}
            >
              <ListItemIcon>
                <span
                  style={{
                    padding: '0 8px 0 8px',
                    fontWeight: 700,
                    fontSize: 12,
                  }}
                >
                  #
                </span>
              </ListItemIcon>
              <ListItemText
                primary={
                  <div>
                    {this.SortHeader('type', 'Type', true)}
                    {this.SortHeader('default_value', 'Name', true)}
                    {this.SortHeader('in_platform', 'Already in plat.', true)}
                    {this.SortHeader('nb_dependencies', 'Dependencies', true)}
                    {this.SortHeader(
                      'nb_inbound_dependencies',
                      'Impacted',
                      true,
                    )}
                    {this.SortHeader('created', 'Creation date', true)}
                  </div>
                }
              />
              <ListItemSecondaryAction>
                <IconButton color="primary" disabled={true} size="small">
                  <CodeJson fontSize="small" />
                </IconButton>
                <Checkbox
                  edge="end"
                  onChange={this.handleToggleAll.bind(this)}
                  checked={checkAll}
                />
              </ListItemSecondaryAction>
            </ListItem>
            {sortedObjectsWithDependencies.map((object) => {
              const type = object.type === 'x-opencti-simple-observable'
                ? observableKeyToType(object.key)
                : convertStixType(object.type);
              const isDisabled = entityId === object.id
                || (!checkedObjects.includes(object.id)
                  && !uncheckedObjects.includes(object.id));
              const isInPlatform = resolvedObjects[object.id] !== undefined;
              return (
                <div key={object.id}>
                  <ListItem classes={{ root: classes.item }} divider={true}>
                    <ListItemIcon color="primary">
                      <ItemIcon type={type} />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <div>
                          <div
                            className={classes.bodyItem}
                            style={inlineStyles.type}
                          >
                            {[
                              'relationship',
                              'sighting',
                              'report',
                              'note',
                              'opinion',
                            ].includes(object.type) ? (
                                type
                              ) : (
                              <Select
                                variant="standard"
                                labelId="type"
                                value={type}
                                onChange={this.handleChangeType.bind(
                                  this,
                                  object.id,
                                )}
                                style={{
                                  margin: 0,
                                  width: '80%',
                                  height: '100%',
                                }}
                              >
                                {scoTypes.includes(type)
                                  ? scoTypes.map((n) => (
                                      <MenuItem key={n} value={n}>
                                        {t(`entity_${n}`)}
                                      </MenuItem>
                                  ))
                                  : sdoTypes.map((n) => (
                                      <MenuItem key={n} value={n}>
                                        {t(`entity_${n}`)}
                                      </MenuItem>
                                  ))}
                              </Select>
                              )}
                          </div>
                          <div
                            className={classes.bodyItem}
                            style={inlineStyles.default_value}
                          >
                            {object.default_value}
                          </div>
                          <div
                            className={classes.bodyItem}
                            style={inlineStyles.in_platform}
                          >
                            <ItemBoolean
                              variant="inList"
                              status={isInPlatform}
                              label={isInPlatform ? t('Yes') : t('No')}
                            />
                          </div>
                          <div
                            className={classes.bodyItem}
                            style={inlineStyles.nb_dependencies}
                          >
                            {object.nb_dependencies}
                          </div>
                          <div
                            className={classes.bodyItem}
                            style={inlineStyles.nb_inbound_dependencies}
                          >
                            {object.nb_inbound_dependencies}
                          </div>
                          <div
                            className={classes.bodyItem}
                            style={inlineStyles.created}
                          >
                            {nsdt(object.created)}
                          </div>
                        </div>
                      }
                    />
                    <ListItemSecondaryAction>
                      <IconButton
                        onClick={this.handleOpenJson.bind(
                          this,
                          JSON.stringify(indexedObjects[object.id], null, 2),
                        )}
                        size="small"
                      >
                        <CodeJson fontSize="small" />
                      </IconButton>
                      <Checkbox
                        edge="end"
                        onChange={this.handleToggleItem.bind(this, object.id)}
                        checked={checkedObjects.includes(object.id)}
                        disabled={isDisabled}
                      />
                    </ListItemSecondaryAction>
                  </ListItem>
                  {object.object_refs && (
                    <List component="div" disablePadding>
                      {object.object_refs.map((objectRef) => {
                        const subObject = indexedObjectsWithDependencies[objectRef]
                          || resolvedObjects[objectRef];
                        if (!subObject) {
                          const subObjectTypeRaw = objectRef.split('--')[0];
                          const subObjectType = subObjectTypeRaw === 'x-opencti-simple-observable'
                            ? observableKeyToType(subObjectTypeRaw)
                            : convertStixType(subObjectTypeRaw);
                          const isSubObjectDisabled = uncheckedObjects.includes(objectRef)
                            || (!(containersChecked[object.id] || []).includes(
                              objectRef,
                            )
                              && !(containersUnchecked[object.id] || []).includes(
                                objectRef,
                              ));
                          const isRefInPlatform = resolvedObjects[objectRef] !== undefined;
                          return (
                            <ListItem
                              key={objectRef}
                              classes={{ root: classes.itemNested }}
                              divider={true}
                            >
                              <ListItemIcon color="primary">
                                <ItemIcon type={subObjectType} />
                              </ListItemIcon>
                              <ListItemText
                                primary={
                                  <div>
                                    <div
                                      className={classes.bodyItem}
                                      style={inlineStyles.type}
                                    >
                                      {subObjectType}
                                    </div>
                                    <div
                                      className={classes.bodyItem}
                                      style={inlineStyles.default_value}
                                    >
                                      {objectRef}
                                    </div>
                                    <div
                                      className={classes.bodyItem}
                                      style={inlineStyles.in_platform}
                                    >
                                      <ItemBoolean
                                        variant="inList"
                                        status={isRefInPlatform}
                                        label={
                                          isRefInPlatform ? t('Yes') : t('No')
                                        }
                                      />
                                    </div>
                                    <div
                                      className={classes.bodyItem}
                                      style={inlineStyles.nb_dependencies}
                                    >
                                      {0}
                                    </div>
                                    <div
                                      className={classes.bodyItem}
                                      style={
                                        inlineStyles.nb_inbound_dependencies
                                      }
                                    >
                                      {0}
                                    </div>
                                    <div
                                      className={classes.bodyItem}
                                      style={inlineStyles.created}
                                    >
                                      {t('N/A')}
                                    </div>
                                  </div>
                                }
                              />
                              <ListItemSecondaryAction>
                                <Checkbox
                                  edge="end"
                                  onChange={this.handleToggleContainerItem.bind(
                                    this,
                                    object.id,
                                    objectRef,
                                  )}
                                  checked={(
                                    containersChecked[object.id] || []
                                  ).includes(objectRef)}
                                  disabled={isSubObjectDisabled}
                                />
                              </ListItemSecondaryAction>
                            </ListItem>
                          );
                        }
                        const subObjectType = subObject.type === 'x-opencti-simple-observable'
                          ? observableKeyToType(subObject.key)
                          : convertStixType(subObject.type);
                        const isSubObjectDisabled = uncheckedObjects.includes(subObject.id)
                          || (!(containersChecked[object.id] || []).includes(
                            subObject.id,
                          )
                            && !(containersUnchecked[object.id] || []).includes(
                              subObject.id,
                            ));
                        const isRefInPlatform = resolvedObjects[objectRef] !== undefined;
                        return (
                          <ListItem
                            key={subObject.id}
                            classes={{ root: classes.itemNested }}
                            divider={true}
                            button={true}
                            onClick={this.handleOpenJson.bind(
                              this,
                              JSON.stringify(
                                indexedObjects[subObject.id],
                                null,
                                2,
                              ),
                            )}
                          >
                            <ListItemIcon color="primary">
                              <ItemIcon type={subObjectType} />
                            </ListItemIcon>
                            <ListItemText
                              primary={
                                <div>
                                  <div
                                    className={classes.bodyItem}
                                    style={inlineStyles.type}
                                  >
                                    {subObjectType}
                                  </div>
                                  <div
                                    className={classes.bodyItem}
                                    style={inlineStyles.default_value}
                                  >
                                    {subObject.default_value}
                                  </div>
                                  <div
                                    className={classes.bodyItem}
                                    style={inlineStyles.in_platform}
                                  >
                                    <ItemBoolean
                                      variant="inList"
                                      status={isRefInPlatform}
                                      label={
                                        isRefInPlatform ? t('Yes') : t('No')
                                      }
                                    />
                                  </div>
                                  <div
                                    className={classes.bodyItem}
                                    style={inlineStyles.nb_dependencies}
                                  >
                                    {subObject.nb_dependencies}
                                  </div>
                                  <div
                                    className={classes.bodyItem}
                                    style={inlineStyles.nb_inbound_dependencies}
                                  >
                                    {subObject.nb_inbound_dependencies}
                                  </div>
                                  <div
                                    className={classes.bodyItem}
                                    style={inlineStyles.created}
                                  >
                                    {nsdt(subObject.created)}
                                  </div>
                                </div>
                              }
                            />
                            <ListItemSecondaryAction>
                              <Checkbox
                                edge="end"
                                onChange={this.handleToggleContainerItem.bind(
                                  this,
                                  object.id,
                                  subObject.id,
                                )}
                                checked={(
                                  containersChecked[object.id] || []
                                ).includes(subObject.id)}
                                disabled={isSubObjectDisabled}
                              />
                            </ListItemSecondaryAction>
                          </ListItem>
                        );
                      })}
                    </List>
                  )}
                </div>
              );
            })}
          </List>
        </Paper>
        <PendingFileToolBar
          handleValidate={this.handleOpenValidate.bind(this)}
          handleDrop={this.handleDrop.bind(this)}
          numberOfSelectedElements={checkedObjects.length}
          isDeleteActive={file.works.length > 0}
        />
        <Formik
          enableReinitialize={true}
          initialValues={{ connector_id: connectors.length > 0 ? connectors[0].id : '' }}
          validationSchema={importValidation(t)}
          onSubmit={this.onSubmitValidate.bind(this)}
          onReset={this.handleCloseValidate.bind(this)}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form style={{ margin: '0 0 20px 0' }}>
              <Dialog
                open={dataToValidate}
                PaperProps={{ elevation: 1 }}
                keepMounted={true}
                onClose={this.handleCloseValidate.bind(this)}
                fullWidth={true}
              >
                <DialogTitle>{t('Validate and send for import')}</DialogTitle>
                <DialogContent>
                  <Field
                    component={SelectField}
                    variant="standard"
                    name="connector_id"
                    label={t('Connector')}
                    fullWidth={true}
                    containerstyle={{ width: '100%' }}
                  >
                    {connectors.map((connector) => {
                      const disabled = !dataToValidate;
                      return (
                        <MenuItem
                          key={connector.id}
                          value={connector.id}
                          disabled={disabled || !connector.active}
                        >
                          {connector.name}
                        </MenuItem>
                      );
                    })}
                  </Field>
                </DialogContent>
                <DialogActions>
                  <Button onClick={handleReset} disabled={isSubmitting}>
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                  >
                    {t('Create')}
                  </Button>
                </DialogActions>
              </Dialog>
            </Form>
          )}
        </Formik>
        <Dialog
          open={displayJson}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          onClick={this.handleCloseJson.bind(this)}
          fullWidth={true}
        >
          <DialogTitle>{t('JSON content')}</DialogTitle>
          <DialogContent>
            <pre>{currentJson}</pre>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseJson.bind(this)}
              classes={{ root: classes.button }}
            >
              {t('Close')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

PendingFileContentComponent.propTypes = {
  file: PropTypes.object,
  stixDomainObjectTypes: PropTypes.array,
  observableTypes: PropTypes.array,
  connectorsImport: PropTypes.array,
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const PendingFileContent = createFragmentContainer(
  PendingFileContentComponent,
  {
    connectorsImport: graphql`
      fragment PendingFileContent_connectorsImport on Connector
      @relay(plural: true) {
        id
        name
        active
        only_contextual
        connector_scope
        updated_at
      }
    `,
    file: graphql`
      fragment PendingFileContent_file on File {
        id
        name
        uploadStatus
        lastModified
        lastModifiedSinceMin
        metaData {
          mimetype
          encoding
          list_filters
          messages {
            timestamp
            message
          }
          errors {
            timestamp
            message
          }
          entity_id
          entity {
            id
            standard_id
            entity_type
            ... on AttackPattern {
              name
            }
            ... on Campaign {
              name
            }
            ... on Report {
              name
            }
            ... on CourseOfAction {
              name
            }
            ... on Individual {
              name
            }
            ... on Organization {
              name
            }
            ... on Sector {
              name
            }
            ... on System {
              name
            }
            ... on Indicator {
              name
            }
            ... on Infrastructure {
              name
            }
            ... on IntrusionSet {
              name
            }
            ... on Position {
              name
            }
            ... on City {
              name
            }
            ... on Country {
              name
            }
            ... on Region {
              name
            }
            ... on Malware {
              name
            }
            ... on ThreatActor {
              name
            }
            ... on Tool {
              name
            }
            ... on Vulnerability {
              name
            }
            ... on Incident {
              name
            }
            ... on StixCyberObservable {
              observable_value
            }
          }
        }
        works {
          id
        }
        ...FileWork_file
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withRouter,
  withTheme,
  withStyles(styles),
)(PendingFileContent);
