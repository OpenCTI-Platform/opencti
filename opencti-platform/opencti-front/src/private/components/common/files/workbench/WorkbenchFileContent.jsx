import {
  Add,
  ArrowDropDown,
  ArrowDropUp,
  CheckCircleOutlined,
  Close,
  DeleteOutlined,
  DoubleArrow,
} from '@mui/icons-material';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Checkbox from '@mui/material/Checkbox';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogTitle from '@mui/material/DialogTitle';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import IconButton from '@mui/material/IconButton';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import ListItemText from '@mui/material/ListItemText';
import MenuItem from '@mui/material/MenuItem';
import Select from '@mui/material/Select';
import Slide from '@mui/material/Slide';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import Axios from 'axios';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import React, { useEffect, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useHistory } from 'react-router-dom';
import { v4 as uuid } from 'uuid';
import * as Yup from 'yup';
import DateTimePickerField from '../../../../../components/DateTimePickerField';
import { useFormatter } from '../../../../../components/i18n';
import ItemBoolean from '../../../../../components/ItemBoolean';
import ItemIcon from '../../../../../components/ItemIcon';
import MarkdownField from '../../../../../components/MarkdownField';
import SelectField from '../../../../../components/SelectField';
import StixItemLabels from '../../../../../components/StixItemLabels';
import StixItemMarkings from '../../../../../components/StixItemMarkings';
import SwitchField from '../../../../../components/SwitchField';
import TextField from '../../../../../components/TextField';
import {
  APP_BASE_PATH,
  commitMutation,
  MESSAGING$,
  QueryRenderer,
} from '../../../../../relay/environment';
import {
  observableValue,
  resolveIdentityClass,
  resolveIdentityType,
  resolveLink,
  resolveLocationType,
  resolveThreatActorType,
} from '../../../../../utils/Entity';
import { defaultKey, defaultValue } from '../../../../../utils/Graph';
import useAttributes from '../../../../../utils/hooks/useAttributes';
import useVocabularyCategory from '../../../../../utils/hooks/useVocabularyCategory';
import {
  computeDuplicates,
  convertFromStixType,
  convertToStixType,
  truncate,
  uniqWithByFields,
} from '../../../../../utils/String';
import { buildDate, now } from '../../../../../utils/Time';
import { isEmptyField, isNotEmptyField } from '../../../../../utils/utils';
import { stixCyberObservablesLinesSearchQuery } from '../../../observations/stix_cyber_observables/StixCyberObservablesLines';
import CreatedByField from '../../form/CreatedByField';
import DynamicResolutionField from '../../form/DynamicResolutionField';
import { ExternalReferencesField } from '../../form/ExternalReferencesField';
import ObjectLabelField from '../../form/ObjectLabelField';
import ObjectMarkingField from '../../form/ObjectMarkingField';
import OpenVocabField from '../../form/OpenVocabField';
import { stixDomainObjectsLinesSearchQuery } from '../../stix_domain_objects/StixDomainObjectsLines';
import { fileManagerAskJobImportMutation } from '../FileManager';
import WorkbenchFilePopover from './WorkbenchFilePopover';
import WorkbenchFileToolbar from './WorkbenchFileToolbar';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import RichTextField from '../../../../../components/RichTextField';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const useStyles = makeStyles((theme) => ({
  container: {
    margin: 0,
  },
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  linesContainer: {
    marginTop: 0,
  },
  item: {
    paddingLeft: 10,
    height: 50,
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
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  sortIcon: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
  },
}));

const inlineStylesHeaders = {
  ttype: {
    float: 'left',
    width: '18%',
    fontSize: 12,
    fontWeight: '700',
  },
  default_value: {
    float: 'left',
    width: '30%',
    fontSize: 12,
    fontWeight: '700',
  },
  labels: {
    float: 'left',
    width: '22%',
    fontSize: 12,
    fontWeight: '700',
  },
  markings: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  in_platform: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
  },
};

const inlineStyles = {
  ttype: {
    float: 'left',
    width: '18%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  default_value: {
    float: 'left',
    width: '30%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  labels: {
    float: 'left',
    width: '22%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  markings: {
    float: 'left',
    width: '20%',
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
};

export const workbenchFileContentAttributesQuery = graphql`
  query WorkbenchFileContentAttributesQuery($elementType: [String]!) {
    schemaAttributes(elementType: $elementType) {
      edges {
        node {
          value
        }
      }
    }
  }
`;

const workbenchFileContentMutation = graphql`
  mutation WorkbenchFileContentMutation($file: Upload!, $entityId: String) {
    uploadPending(file: $file, entityId: $entityId) {
      id
    }
  }
`;

const importValidation = (t) => Yup.object().shape({
  connector_id: Yup.string().required(t('This field is required')),
});

const WorkbenchFileContentComponent = ({
  connectorsImport,
  file,
  stixDomainObjectTypes,
  observableTypes,
}) => {
  const {
    booleanAttributes,
    dateAttributes,
    ignoredAttributes,
    markdownAttributes,
    htmlAttributes,
    multipleAttributes,
    numberAttributes,
    workbenchAttributes,
    typesContainers,
    vocabularyAttributes,
  } = useAttributes();
  const { fieldToCategory, getFieldDefinition } = useVocabularyCategory();
  const { t } = useFormatter();
  const history = useHistory();
  const classes = useStyles();

  // region state
  const [currentTab, setCurrentTab] = useState(0);

  const [stixDomainObjects, setStixDomainObjects] = useState([]);
  const [stixCyberObservables, setStixCyberObservables] = useState([]);
  const [stixCoreRelationships, setStixCoreRelationships] = useState([]);
  const [containers, setContainers] = useState([]);

  const [selectedElements, setSelectedElements] = useState({});
  const [deSelectedElements, setDeselectedElements] = useState({});
  const [selectAll, setSelectAll] = useState(false);
  const [containerSelectAll, setContainerSelectAll] = useState(false);
  const [containerSelectedElements, setContainerSelectedElements] = useState();
  const [containerDeselectedElements, setContainerDeselectedElements] = useState();

  const [deleteObject, setDeleteObject] = useState();
  const [entityStep, setEntityStep] = useState();
  const [entityType, setEntityType] = useState();
  const [entityId, setEntityId] = useState();
  const [displayObservable, setDispayObservable] = useState(false);
  const [observableType, setObservableType] = useState();
  const [observableId, setObservableId] = useState();
  const [containerStep, setContainerStep] = useState();
  const [containerType, setContainerType] = useState();
  const [containerId, setContainerId] = useState();
  const [relationshipId, setRelationshipId] = useState();

  const [displayValidate, setDisplayValidate] = useState(false);

  const [sortBy, setSortBy] = useState('default_value');
  const [orderAsc, setOrderAsc] = useState(true);
  const [containerSortBy, setContainerSortBy] = useState('default_value');
  const [containerOrderAsc, setContainerOrderAsc] = useState(true);

  const computeState = (objects) => {
    const sdoTypes = [
      ...stixDomainObjectTypes.edges.map((n) => convertToStixType(n.node.id)),
      'threat-actor',
      'marking-definition',
      'identity',
      'location',
    ].filter((n) => !typesContainers.includes(n));
    const scoTypes = observableTypes.edges.map((n) => convertToStixType(n.node.id));
    const newStixDomainObjects = objects
      .filter((n) => sdoTypes.includes(n.type) && n.id)
      .map((n) => (typeof n.definition === 'object' && !n.name
        ? { ...n, name: R.toPairs(n.definition)[0][1] }
        : n));
    const newStixCyberObservables = objects.filter(
      (n) => scoTypes.includes(n.type) && n.id,
    );
    const newStixCoreRelationships = objects.filter(
      (n) => n.type === 'relationship' && n.id,
    );
    const newContainers = objects.filter(
      (n) => typesContainers.includes(n.type) && n.id,
    );
    setStixDomainObjects(newStixDomainObjects);
    setStixCyberObservables(newStixCyberObservables);
    setStixCoreRelationships(newStixCoreRelationships);
    setContainers(newContainers);
  };
  // endregion

  // region file
  const loadFileContent = () => {
    const url = `${APP_BASE_PATH}/storage/view/${encodeURIComponent(file.id)}`;
    Axios.get(url).then(async (res) => {
      computeState(res.data.objects);
      return true;
    });
  };

  const saveFile = () => {
    let currentEntityId = null;
    if (file.metaData.entity_id && file.metaData.entity) {
      currentEntityId = file.metaData.entity_id;
    }
    // update entity container objects_refs
    if (currentEntityId) {
      const currentEntityContainer = containers.find(
        (container) => container.x_opencti_id === currentEntityId,
      );
      if (currentEntityContainer) {
        const currentEntityObjectRefs = Array.isArray(
          currentEntityContainer.object_refs,
        )
          ? currentEntityContainer.object_refs
          : [];
        const objectIds = [...stixDomainObjects, ...stixCyberObservables].map(
          (s) => s.id,
        );
        currentEntityContainer.object_refs = R.uniq([
          ...currentEntityObjectRefs,
          ...objectIds,
        ]);
      }
    }
    console.log([
      ...stixDomainObjects,
      ...stixCyberObservables,
      ...stixCoreRelationships,
      ...containers,
    ]);
    const data = {
      id: `bundle--${uuid()}`,
      type: 'bundle',
      objects: [
        ...stixDomainObjects,
        ...stixCyberObservables,
        ...stixCoreRelationships,
        ...containers,
      ],
    };
    const json = JSON.stringify(data);
    const blob = new Blob([json], { type: 'text/json' });
    const fileToUpload = new File([blob], file.name, {
      type: 'application/json',
    });
    commitMutation({
      mutation: workbenchFileContentMutation,
      variables: { file: fileToUpload, entityId: currentEntityId },
    });
  };

  useEffect(() => loadFileContent(), []);
  useEffect(
    () => saveFile(),
    [
      JSON.stringify(stixDomainObjects),
      JSON.stringify(stixCyberObservables),
      JSON.stringify(stixCoreRelationships),
      JSON.stringify(containers),
    ],
  );
  // endregion

  // region utils
  const findEntityById = (id) => stixDomainObjects.filter((n) => n.id === id).at(0);

  const connectors = connectorsImport.filter(({ connector_scope }) => connector_scope.includes('application/json'));
  let numberOfSelectedElements = Object.keys(selectedElements || {}).length;
  let elements = [];
  if (currentTab === 0) {
    elements = stixDomainObjects;
  } else if (currentTab === 1) {
    elements = stixCyberObservables;
  } else if (currentTab === 2) {
    elements = stixCoreRelationships;
  } else if (currentTab === 3) {
    elements = containers;
  }
  if (selectAll) {
    numberOfSelectedElements = elements.length - Object.keys(deSelectedElements || {}).length;
  }
  // endregion

  // region control
  const handleOpenValidate = () => setDisplayValidate(true);
  const handleCloseValidate = () => setDisplayValidate(false);

  const handleChangeTab = (_, index) => {
    setCurrentTab(index);
    setSelectedElements(null);
    setDeselectedElements(null);
    setSelectAll(false);
  };

  const handleToggleSelectAll = () => {
    setSelectedElements(null);
    setDeselectedElements(null);
    setSelectAll(!selectAll);
  };
  const handleClearSelectedElements = () => {
    setSelectedElements(null);
    setDeselectedElements(null);
    setSelectAll(false);
  };
  const handleToggleSelectObject = (object, event) => {
    event.stopPropagation();
    event.preventDefault();
    if (object.id in (selectedElements || {})) {
      const newSelectedElements = R.omit([object.id], selectedElements);
      setSelectAll(false);
      setSelectedElements(newSelectedElements);
    } else if (selectAll && object.id in (deSelectedElements || {})) {
      const newDeSelectedElements = R.omit([object.id], deSelectedElements);
      setDeselectedElements(newDeSelectedElements);
    } else if (selectAll) {
      const newDeSelectedElements = R.assoc(
        object.id,
        object,
        deSelectedElements || {},
      );
      setDeselectedElements(newDeSelectedElements);
    } else {
      const newSelectedElements = R.assoc(
        object.id,
        object,
        selectedElements || {},
      );
      setSelectAll(false);
      setSelectedElements(newSelectedElements);
    }
  };
  const handleDeleteObject = (object) => setDeleteObject(object);
  const handleCloseDeleteObject = () => setDeleteObject(null);

  const handleOpenEntity = (type, id) => {
    setEntityStep(0);
    setEntityType(convertFromStixType(type));
    setEntityId(id);
  };
  const handleCloseEntity = () => {
    setEntityStep(null);
    setEntityType(null);
    setEntityId(null);
  };

  const handleOpenRelationship = (id) => setRelationshipId(id);
  const handleCloseRelationship = () => setRelationshipId(null);

  const handleOpenObservable = (type, id) => {
    setDispayObservable(true);
    setObservableType(convertFromStixType(type));
    setObservableId(id);
  };
  const handleCloseObservable = () => {
    setDispayObservable(false);
    setObservableType(null);
    setObservableId(null);
  };

  const handleOpenContainer = (type, id) => {
    setContainerStep(0);
    setContainerType(convertFromStixType(type));
    setContainerId(id);
  };
  const handleCloseContainer = () => {
    setContainerStep(null);
    setContainerType(null);
    setContainerId(null);
  };

  const handleToggleContainerSelectAll = () => {
    setContainerSelectAll(!containerSelectAll);
    setContainerSelectedElements(null);
    setContainerDeselectedElements(null);
  };

  const handleToggleContainerSelectObject = (object, event) => {
    event.stopPropagation();
    event.preventDefault();
    if (object.id in (containerSelectedElements || {})) {
      const newSelectedElements = R.omit(
        [object.id],
        containerSelectedElements,
      );
      setContainerSelectAll(false);
      setContainerSelectedElements(newSelectedElements);
    } else if (
      containerSelectAll
      && object.id in (containerDeselectedElements || {})
    ) {
      const newDeSelectedElements = R.omit(
        [object.id],
        containerDeselectedElements,
      );
      setContainerDeselectedElements(newDeSelectedElements);
    } else if (containerSelectAll) {
      const newDeSelectedElements = R.assoc(
        object.id,
        object,
        containerDeselectedElements || {},
      );
      setContainerDeselectedElements(newDeSelectedElements);
    } else {
      const newSelectedElements = R.assoc(
        object.id,
        object,
        containerSelectedElements || {},
      );
      setContainerSelectAll(false);
      setContainerSelectedElements(newSelectedElements);
    }
  };

  const handleDeleteObjects = () => {
    let objects = [];
    if (currentTab === 0) {
      objects = stixDomainObjects;
    } else if (currentTab === 1) {
      objects = stixCyberObservables;
    } else if (currentTab === 2) {
      objects = stixCoreRelationships;
    } else if (currentTab === 3) {
      objects = containers;
    }
    let objectsToBeDeletedIds;
    if (selectAll) {
      objectsToBeDeletedIds = objects
        .filter((n) => !Object.keys(deSelectedElements || {}).includes(n.id))
        .map((n) => n.id);
    } else {
      objectsToBeDeletedIds = objects
        .filter((n) => Object.keys(selectedElements || {}).includes(n.id))
        .map((n) => n.id);
    }
    // Delete
    let finalStixDomainObjects = stixDomainObjects.filter(
      (n) => !objectsToBeDeletedIds.includes(n.id),
    );
    let finalStixCyberObservables = stixCyberObservables.filter(
      (n) => !objectsToBeDeletedIds.includes(n.id),
    );
    let finalStixCoreRelationships = stixCoreRelationships.filter(
      (n) => !objectsToBeDeletedIds.includes(n.id),
    );
    let finalContainers = containers.filter(
      (n) => !objectsToBeDeletedIds.includes(n.id),
    );

    // In case one of the object is an author
    finalStixDomainObjects = finalStixDomainObjects.map((n) => (objectsToBeDeletedIds.includes(n.created_by_ref)
      ? R.dissoc('created_by_ref', n)
      : n));
    finalStixCyberObservables = finalStixCyberObservables.map((n) => (objectsToBeDeletedIds.includes(n.created_by_ref)
      ? R.dissoc('created_by_ref', n)
      : n));
    finalStixCoreRelationships = finalStixCoreRelationships.map((n) => (objectsToBeDeletedIds.includes(n.created_by_ref)
      ? R.dissoc('created_by_ref', n)
      : n));
    finalContainers = finalContainers.map((n) => (objectsToBeDeletedIds.includes(n.created_by_ref)
      ? R.dissoc('created_by_ref', n)
      : n));

    // In case on of the object is a marking
    finalStixDomainObjects = finalStixDomainObjects.map((n) => R.assoc(
      'object_marking_refs',
      n.object_marking_refs?.filter(
        (o) => !objectsToBeDeletedIds.includes(o),
      ),
      n,
    ));
    finalStixCyberObservables = finalStixCyberObservables.map((n) => R.assoc(
      'object_marking_refs',
      n.object_marking_refs?.filter(
        (o) => !objectsToBeDeletedIds.includes(o),
      ),
      n,
    ));
    finalStixCoreRelationships = finalStixCoreRelationships.map((n) => R.assoc(
      'object_marking_refs',
      n.object_marking_refs?.filter(
        (o) => !objectsToBeDeletedIds.includes(o),
      ),
      n,
    ));
    finalContainers = finalContainers.map((n) => R.assoc(
      'object_marking_refs',
      n.object_marking_refs?.filter(
        (o) => !objectsToBeDeletedIds.includes(o),
      ),
      n,
    ));
    // Impact
    const stixCoreRelationshipsToRemove = finalStixCoreRelationships
      .filter(
        (n) => objectsToBeDeletedIds.includes(n.source_ref)
          || objectsToBeDeletedIds.includes(n.target_ref),
      )
      .map((n) => n.id);
    finalContainers = finalContainers.map((n) => R.assoc(
      'object_refs',
      (n.object_refs || []).filter(
        (o) => !objectsToBeDeletedIds.includes(o)
            && !stixCoreRelationshipsToRemove.includes(o),
      ),
      n,
    ));
    finalStixCoreRelationships = finalStixCoreRelationships.filter(
      (n) => !stixCoreRelationshipsToRemove.includes(n.id),
    );
    setStixDomainObjects(finalStixDomainObjects);
    setStixCyberObservables(finalStixCyberObservables);
    setStixCoreRelationships(finalStixCoreRelationships);
    setContainers(finalContainers);
    setSelectedElements(null);
    setDeselectedElements(null);
    setSelectAll(false);
  };

  const handleChangeObservableType = (id, event) => {
    const observable = R.head(stixCyberObservables.filter((n) => n.id === id)) || {};
    const stixType = convertToStixType(event.target.value);
    let updatedObservable = {
      ...observable,
      id: `${stixType}--${uuid()}`,
      type: stixType,
    };
    // Properly handle conversion
    if (observable.type === 'file') {
      if (observable.name) {
        updatedObservable = { ...updatedObservable, value: observable.name };
      }
    } else if (stixType === 'file') {
      if (observable.value) {
        updatedObservable = { ...updatedObservable, name: observable.value };
      }
    }
    const updatedStixCoreRelationships = stixCoreRelationships.map((n) => {
      if (n.source_ref === id) {
        return R.assoc('source_ref', updatedObservable.id, n);
      }
      if (n.target_ref === id) {
        return R.assoc('target_ref', updatedObservable.id, n);
      }
      return n;
    });
    const updatedContainers = containers.map((n) => {
      if ((n.object_refs || []).includes(id)) {
        return R.assoc(
          'object_refs',
          [
            ...(n.object_refs || []).filter((o) => o !== id),
            updatedObservable.id,
          ],
          n,
        );
      }
      return n;
    });
    const observableDefaultKey = defaultKey(updatedObservable);
    const observablesOfSameTypeAndKey = stixCyberObservables.filter(
      (n) => n.type === updatedObservable.type
        && observableDefaultKey
        && n[observableDefaultKey]
        && n[observableDefaultKey].length > 0,
    );
    const otherObservables = stixCyberObservables.filter(
      (n) => n.type !== updatedObservable.type
        || !observableDefaultKey
        || !n[observableDefaultKey]
        || n[observableDefaultKey].length === 0,
    );
    setStixCyberObservables([
      ...uniqWithByFields(
        observableDefaultKey ? [observableDefaultKey, 'type'] : ['id'],
        R.uniqBy(R.prop('id'), [
          ...observablesOfSameTypeAndKey.filter((n) => n.id !== observable.id),
          updatedObservable,
        ]),
      ),
      ...otherObservables.filter((n) => n.id !== observable.id),
    ]);
    setStixCoreRelationships(updatedStixCoreRelationships);
    setContainers(updatedContainers);
  };
  // endregion

  // region submission
  const onSubmitValidate = (values, { setSubmitting, resetForm }) => {
    let currentEntityId = null;
    if (file.metaData.entity_id && file.metaData.entity) {
      currentEntityId = file.metaData.entity_id;
    }
    const data = {
      id: `bundle--${uuid()}`,
      type: 'bundle',
      objects: [
        ...stixDomainObjects,
        ...stixCyberObservables,
        ...stixCoreRelationships,
        ...containers,
      ],
    };
    const json = JSON.stringify(data);
    const blob = new Blob([json], { type: 'text/json' });
    const fileToUpload = new File([blob], file.name, {
      type: 'application/json',
    });
    commitMutation({
      mutation: workbenchFileContentMutation,
      variables: { file: fileToUpload, entityId: currentEntityId },
      onCompleted: () => {
        setTimeout(() => {
          commitMutation({
            mutation: fileManagerAskJobImportMutation,
            variables: {
              fileName: file.id,
              connectorId: values.connector_id,
              bypassValidation: true,
            },
            onCompleted: () => {
              setSubmitting(false);
              resetForm();
              setDisplayValidate(false);
              MESSAGING$.notifySuccess('Import successfully asked');
              if (file.metaData.entity) {
                const entityLink = `${resolveLink(
                  file.metaData.entity.entity_type,
                )}/${file.metaData.entity.id}`;
                history.push(`${entityLink}/files`);
              } else {
                history.push('/dashboard/import');
              }
            },
          });
        }, 2000);
      },
    });
  };

  const onSubmitApplyMarking = (values) => {
    const markingDefinitions = R.pluck('entity', values.objectMarking).map(
      (n) => ({
        ...n,
        id: n.standard_id || n.id,
        name: n.name || n.definition,
        type: 'marking-definition',
      }),
    );
    let objects = [];
    if (currentTab === 0) {
      objects = stixDomainObjects;
    } else if (currentTab === 1) {
      objects = stixCyberObservables;
    } else if (currentTab === 2) {
      objects = stixCoreRelationships;
    } else if (currentTab === 3) {
      objects = containers;
    }
    let objectsToBeProcessed;
    if (selectAll) {
      objectsToBeProcessed = objects.filter(
        (n) => !Object.keys(deSelectedElements || {}).includes(n.id),
      );
    } else {
      objectsToBeProcessed = objects.filter((n) => Object.keys(selectedElements || {}).includes(n.id));
    }
    let finalStixDomainObjects = stixDomainObjects;
    let finalStixCyberObservables = stixCyberObservables;
    let finalStixCoreRelationships = stixCoreRelationships;
    let finalContainers = containers;
    if (currentTab === 0) {
      finalStixDomainObjects = objectsToBeProcessed.map((n) => R.assoc(
        'object_marking_refs',
        R.uniq([
          ...(n.object_marking_refs || []),
          ...markingDefinitions.map((o) => o.id),
        ]),
        n,
      ));
    } else if (currentTab === 1) {
      finalStixCyberObservables = objectsToBeProcessed.map((n) => R.assoc(
        'object_marking_refs',
        R.uniq([
          ...(n.object_marking_refs || []),
          ...markingDefinitions.map((o) => o.id),
        ]),
        n,
      ));
    } else if (currentTab === 2) {
      finalStixCoreRelationships = objectsToBeProcessed.map((n) => R.assoc(
        'object_marking_refs',
        R.uniq([
          ...(n.object_marking_refs || []),
          ...markingDefinitions.map((o) => o.id),
        ]),
        n,
      ));
    } else if (currentTab === 3) {
      finalContainers = objectsToBeProcessed.map((n) => R.assoc(
        'object_marking_refs',
        R.uniq([
          ...(n.object_marking_refs || []),
          ...markingDefinitions.map((o) => o.id),
        ]),
        n,
      ));
    }
    setStixDomainObjects(
      R.uniqBy(R.prop('id'), [...finalStixDomainObjects, ...markingDefinitions]),
    );
    setStixCyberObservables(finalStixCyberObservables);
    setStixCoreRelationships(finalStixCoreRelationships);
    setContainers(finalContainers);
  };

  const submitDeleteObject = (obj) => {
    const toDeleteObject = obj ?? deleteObject;
    let finalStixDomainObjects = stixDomainObjects.filter(
      (n) => n.id !== toDeleteObject.id,
    );
    let finalStixCyberObservables = stixCyberObservables.filter(
      (n) => n.id !== toDeleteObject.id,
    );
    let finalStixCoreRelationships = stixCoreRelationships.filter(
      (n) => n.id !== toDeleteObject.id,
    );
    let finalContainers = containers.filter((n) => n.id !== toDeleteObject.id);
    if (toDeleteObject.type === 'identity') {
      finalStixDomainObjects = finalStixDomainObjects.map((n) => (n.created_by_ref === toDeleteObject.id
        ? R.dissoc('created_by_ref', n)
        : n));
      finalStixCyberObservables = finalStixCyberObservables.map((n) => (n.created_by_ref === toDeleteObject.id
        ? R.dissoc('created_by_ref', n)
        : n));
      finalStixCoreRelationships = finalStixCoreRelationships.map((n) => (n.created_by_ref === toDeleteObject.id
        ? R.dissoc('created_by_ref', n)
        : n));
      finalContainers = finalContainers.map((n) => (n.created_by_ref === toDeleteObject.id
        ? R.dissoc('created_by_ref', n)
        : n));
    } else if (toDeleteObject.type === 'marking-definition') {
      finalStixDomainObjects = finalStixDomainObjects.map((n) => R.assoc(
        'object_marking_refs',
        n.object_marking_refs?.filter((o) => o !== toDeleteObject.id),
        n,
      ));
      finalStixCyberObservables = finalStixCyberObservables.map((n) => R.assoc(
        'object_marking_refs',
        n.object_marking_refs?.filter((o) => o !== toDeleteObject.id),
        n,
      ));
      finalStixCoreRelationships = finalStixCoreRelationships.map((n) => R.assoc(
        'object_marking_refs',
        n.object_marking_refs?.filter((o) => o !== toDeleteObject.id),
        n,
      ));
      finalContainers = finalContainers.map((n) => R.assoc(
        'object_marking_refs',
        n.object_marking_refs?.filter((o) => o !== toDeleteObject.id),
        n,
      ));
    }
    // Impact
    const stixCoreRelationshipsToRemove = finalStixCoreRelationships
      .filter(
        (n) => n.source_ref === toDeleteObject.id
          || n.target_ref === toDeleteObject.id,
      )
      .map((n) => n.id);
    finalContainers = finalContainers.map((n) => R.assoc(
      'object_refs',
      (n.object_refs || []).filter(
        (o) => o !== toDeleteObject.id
            && !stixCoreRelationshipsToRemove.includes(o),
      ),
      n,
    ));
    finalStixCoreRelationships = finalStixCoreRelationships.filter(
      (n) => !stixCoreRelationshipsToRemove.includes(n.id),
    );
    setStixDomainObjects(finalStixDomainObjects);
    setStixCyberObservables(finalStixCyberObservables);
    setStixCoreRelationships(finalStixCoreRelationships);
    setContainers(finalContainers);
    setDeleteObject(null);
  };

  const onSubmitEntity = (values) => {
    const entity = R.head(stixDomainObjects.filter((n) => n.id === entityId)) || {};
    const markingDefinitions = R.pluck('entity', values.objectMarking).map(
      (n) => ({
        ...n,
        id: n.standard_id || n.id,
        name: n.name || n.definition,
        type: 'marking-definition',
      }),
    );
    const identity = values.createdBy?.entity
      ? {
        ...values.createdBy.entity,
        id: values.createdBy.entity.standard_id || values.createdBy.entity.id,
        type: 'identity',
      }
      : null;
    const finalValues = {
      ...R.omit(
        ['objectLabel', 'objectMarking', 'createdBy', 'externalReferences'],
        values,
      ),
      labels: R.pluck('label', values.objectLabel),
      object_marking_refs: R.pluck('entity', values.objectMarking).map(
        (n) => n.standard_id || n.id,
      ),
      created_by_ref:
        values.createdBy?.entity?.standard_id || values.createdBy?.entity?.id,
      external_references: R.pluck('entity', values.externalReferences),
    };
    const stixType = convertToStixType(entityType);
    const updatedEntity = {
      ...entity,
      ...finalValues,
      id: entity.id ? entity.id : `${stixType}--${uuid()}`,
      type: stixType,
    };
    if (updatedEntity.type === 'identity' && !updatedEntity.identity_class) {
      updatedEntity.identity_class = resolveIdentityClass(entityType);
    } else if (
      updatedEntity.type === 'location'
      && !updatedEntity.x_opencti_location_type
    ) {
      updatedEntity.x_opencti_location_type = entityType;
    }
    setStixDomainObjects(
      uniqWithByFields(
        ['name', 'type'],
        R.uniqBy(R.prop('id'), [
          ...stixDomainObjects.filter((n) => n.id !== updatedEntity.id),
          ...markingDefinitions,
          ...(identity ? [identity] : []),
          updatedEntity,
        ]),
      ),
    );
    setEntityId(updatedEntity.id);
    setEntityStep(1);
  };

  const onSubmitEntityContext = (values) => {
    const indexedStixObjects = {
      ...R.indexBy(R.prop('id'), stixDomainObjects),
      ...R.indexBy(R.prop('id'), stixCyberObservables),
    };
    const newEntities = Object.keys(values)
      .map((key) => values[key].map((n) => {
        const currentEntityType = n.type;
        const newEntity = {
          id: n.id,
          type: convertToStixType(currentEntityType),
          name: n.name,
        };
        if (newEntity.type === 'identity' && !newEntity.identity_class) {
          newEntity.identity_class = resolveIdentityClass(currentEntityType);
        } else if (
          newEntity.type === 'location'
            && !newEntity.x_opencti_location_type
        ) {
          newEntity.x_opencti_location_type = currentEntityType;
        }
        return newEntity;
      }))
      .flat();
    const newRelationships = Object.keys(values)
      .map((key) => {
        const [relationshipType, direction] = key.split('_');
        return values[key].map((n) => ({
          id: `relationship--${uuid()}`,
          type: 'relationship',
          relationship_type: relationshipType,
          source_ref: direction === 'from' ? entityId : n.id,
          target_ref: direction === 'from' ? n.id : entityId,
        }));
      })
      .flat();
    const fromRelationshipsTypes = Object.keys(values)
      .filter((n) => n.includes('_from'))
      .map((n) => n.split('_')[0]);
    const toRelationshipsTypes = Object.keys(values)
      .filter((n) => n.includes('_to'))
      .map((n) => n.split('_')[0]);
    // Compute relationships to delete
    const stixCoreRelationshipsToDelete = [
      ...stixCoreRelationships.filter(
        (n) => fromRelationshipsTypes.includes(n.relationship_type)
          && n.source_ref === entityId,
      ),
      ...stixCoreRelationships.filter(
        (n) => toRelationshipsTypes.includes(n.relationship_type)
          && n.target_ref === entityId,
      ),
    ];
    // Delete objects, no matter that is parallel it will always success
    stixCoreRelationshipsToDelete.forEach((n) => submitDeleteObject(n));
    const stixCoreRelationshipsToDeleteIds = stixCoreRelationshipsToDelete.map(
      (n) => n.id,
    );
    // Compute the objects to be check for purge in this specific context
    const stixDomainObjectsToCheckForPurging = [
      ...stixCoreRelationships
        .filter(
          (n) => fromRelationshipsTypes.includes(n.relationship_type)
            && n.source_ref === entityId,
        )
        .map((n) => indexedStixObjects[n.target_ref] || null)
        .filter((n) => n !== null),
      ...stixCoreRelationships
        .filter(
          (n) => toRelationshipsTypes.includes(n.relationship_type)
            && n.target_ref === entityId,
        )
        .map((n) => indexedStixObjects[n.source_ref] || null)
        .filter((n) => n !== null),
    ];
    // Check if no relationships point to objects, then purge in this context
    const stixDomainObjectsToDelete = stixDomainObjectsToCheckForPurging
      .map((value) => {
        const rels = stixCoreRelationships.filter(
          (n) => !stixCoreRelationshipsToDeleteIds.includes(n.id)
            && (n.source_ref === value.id || n.target_ref === value.id),
        );
        if (rels.length === 0) {
          return value;
        }
        return null;
      })
      .filter((n) => n !== null);
    stixDomainObjectsToDelete.forEach((n) => submitDeleteObject(n));
    const stixDomainObjectsToDeleteIds = stixDomainObjectsToDelete.map(
      (n) => n.id,
    );
    setStixDomainObjects(
      uniqWithByFields(
        ['name', 'type', 'identity_class', 'x_opencti_location_type'],
        R.uniqBy(R.prop('id'), [
          ...stixDomainObjects.filter(
            (n) => !stixDomainObjectsToDeleteIds.includes(n.id),
          ),
          ...newEntities,
        ]),
      ),
    );
    setStixCoreRelationships(
      uniqWithByFields(
        ['source_ref', 'target_ref', 'relationship_type'],
        R.uniqBy(R.prop('id'), [
          ...stixCoreRelationships.filter(
            (n) => !stixCoreRelationshipsToDeleteIds.includes(n.id),
          ),
          ...newRelationships,
        ]),
      ),
    );
    handleCloseEntity();
  };

  const onSubmitRelationship = (values) => {
    const relationship = R.head(stixCoreRelationships.filter((n) => n.id === relationshipId))
      || {};
    const markingDefinitions = R.pluck('entity', values.objectMarking).map(
      (n) => ({
        ...n,
        id: n.standard_id || n.id,
        name: n.name || n.definition,
        type: 'marking-definition',
      }),
    );
    const identity = values.createdBy?.entity
      ? {
        ...values.createdBy.entity,
        id: values.createdBy.entity.standard_id || values.createdBy.entity.id,
        type: 'identity',
      }
      : null;
    const finalValues = {
      ...R.omit(
        ['objectLabel', 'objectMarking', 'createdBy', 'externalReferences'],
        values,
      ),
      labels: R.pluck('label', values.objectLabel),
      object_marking_refs: R.pluck('entity', values.objectMarking).map(
        (n) => n.standard_id || n.id,
      ),
      created_by_ref:
        values.createdBy?.entity?.standard_id || values.createdBy?.entity?.id,
      external_references: R.pluck('entity', values.externalReferences),
    };
    const updatedRelationship = {
      ...relationship,
      ...finalValues,
      id: relationship.id ? relationship.id : `relationship--${uuid()}`,
    };
    setStixCoreRelationships(
      uniqWithByFields(
        ['source_ref', 'target_ref', 'relationship_type'],
        R.uniqBy(R.prop('id'), [
          ...stixCoreRelationships.filter(
            (n) => n.id !== updatedRelationship.id,
          ),
          updatedRelationship,
        ]),
      ),
    );
    setStixDomainObjects(
      uniqWithByFields(
        ['name', 'type'],
        R.uniqBy(R.prop('id'), [
          ...stixDomainObjects,
          ...markingDefinitions,
          ...(identity ? [identity] : []),
        ]),
      ),
    );
    handleCloseRelationship();
  };

  const onSubmitObservable = (values) => {
    const observable = R.head(stixCyberObservables.filter((n) => n.id === observableId)) || {};
    const markingDefinitions = R.pluck('entity', values.objectMarking).map(
      (n) => ({
        ...n,
        id: n.standard_id || n.id,
        name: n.name || n.definition,
        type: 'marking-definition',
      }),
    );
    const hashes = {};
    if (values.hashes_MD5 && values.hashes_MD5.length > 0) {
      hashes.MD5 = values.hashes_MD5;
    }
    if (values['hashes_SHA-1'] && values['hashes_SHA-1'].length > 0) {
      hashes['SHA-1'] = values['hashes_SHA-1'];
    }
    if (values['hashes_SHA-256'] && values['hashes_SHA-256'].length > 0) {
      hashes['SHA-256'] = values['hashes_SHA-256'];
    }
    if (values['hashes_SHA-512'] && values['hashes_SHA-512'].length > 0) {
      hashes['SHA-512'] = values['hashes_SHA-512'];
    }
    const identity = values.createdBy?.entity
      ? {
        ...values.createdBy.entity,
        id: values.createdBy.entity.standard_id || values.createdBy.entity.id,
        type: 'identity',
      }
      : null;
    let finalValues = {
      ...R.omit(
        [
          'objectLabel',
          'objectMarking',
          'createdBy',
          'externalReferences',
          'hashes_MD5',
          'hashes_SHA-1',
          'hashes_SHA-256',
          'hashes_SHA-512',
        ],
        values,
      ),
      labels: R.pluck('label', values.objectLabel),
      object_marking_refs: R.pluck('entity', values.objectMarking).map(
        (n) => n.standard_id || n.id,
      ),
      created_by_ref:
        values.createdBy?.entity?.standard_id || values.createdBy?.entity?.id,
      external_references: R.pluck('entity', values.externalReferences),
    };
    // numberAttributes must be rewritten to actual number
    const availableKeys = Object.keys(finalValues);
    for (let i = 0; i < numberAttributes.length; i += 1) {
      const numberAttribute = numberAttributes[i];
      if (availableKeys.includes(numberAttribute)) {
        const numericAttr = finalValues[numberAttribute];
        finalValues[numberAttribute] = isEmptyField(numericAttr)
          ? null
          : parseInt(numericAttr, 10);
      }
    }
    if (!R.isEmpty(hashes)) {
      finalValues = { ...finalValues, hashes };
    }
    const stixType = convertToStixType(observableType);
    const updatedObservable = {
      ...observable,
      ...finalValues,
      id: observable.id ? observable.id : `${stixType}--${uuid()}`,
      type: stixType,
      observable_value: observableValue({
        ...observable,
        ...finalValues,
        entity_type: stixType,
      }),
    };
    const observableDefaultKey = defaultKey(updatedObservable);
    const observablesOfSameTypeAndKey = stixCyberObservables.filter(
      (n) => n.type === updatedObservable.type
        && observableDefaultKey
        && n[observableDefaultKey]
        && isNotEmptyField(n[observableDefaultKey]),
    );
    const otherObservables = stixCyberObservables.filter(
      (n) => n.type !== updatedObservable.type
        || !observableDefaultKey
        || !n[observableDefaultKey]
        || isEmptyField(n[observableDefaultKey]),
    );
    const groupedObservablesOfSameTypeAndKey = computeDuplicates(
      observableDefaultKey ? [observableDefaultKey, 'type'] : ['id'],
      R.uniqBy(R.prop('id'), [
        ...observablesOfSameTypeAndKey.filter(
          (n) => n.id !== updatedObservable.id,
        ),
        updatedObservable,
      ]),
    );
    const deduplicatedObservablesOfSameTypeAndKey = R.map(
      (n) => R.mergeAll(n),
      groupedObservablesOfSameTypeAndKey,
    );
    setStixCyberObservables([
      ...deduplicatedObservablesOfSameTypeAndKey,
      ...otherObservables.filter((n) => n.id !== updatedObservable.id),
    ]);
    setStixDomainObjects(
      uniqWithByFields(
        ['name', 'type'],
        R.uniqBy(R.prop('id'), [
          ...stixDomainObjects,
          ...markingDefinitions,
          ...(identity ? [identity] : []),
        ]),
      ),
    );
    handleCloseObservable();
  };

  const onSubmitContainer = (values) => {
    const container = R.head(containers.filter((n) => n.id === containerId)) || {};
    const indexedStixObjects = {
      ...R.indexBy(R.prop('id'), stixDomainObjects),
      ...R.indexBy(R.prop('id'), stixCyberObservables),
      ...R.indexBy(R.prop('id'), stixCoreRelationships),
    };
    const markingDefinitions = R.pluck('entity', values.objectMarking).map(
      (n) => ({
        ...n,
        id: n.standard_id || n.id,
        name: n.name || n.definition,
        type: 'marking-definition',
      }),
    );
    const identity = values.createdBy?.entity
      ? {
        ...values.createdBy.entity,
        id: values.createdBy.entity.standard_id || values.createdBy.entity.id,
        type: 'identity',
      }
      : null;
    const finalValues = {
      ...R.omit(
        ['objectLabel', 'objectMarking', 'createdBy', 'externalReferences'],
        values,
      ),
      labels: R.pluck('label', values.objectLabel),
      object_marking_refs: R.pluck('entity', values.objectMarking).map(
        (n) => n.standard_id || n.id,
      ),
      created_by_ref:
        values.createdBy?.entity?.standard_id || values.createdBy?.entity?.id,
      external_references: R.pluck('entity', values.externalReferences),
    };
    const stixType = convertToStixType(containerType);
    const updatedContainer = {
      ...container,
      ...finalValues,
      id: container.id ? container.id : `${stixType}--${uuid()}`,
      type: stixType,
    };
    setContainers(
      uniqWithByFields(
        ['name', 'type'],
        R.uniqBy(R.prop('id'), [
          ...containers.filter((n) => n.id !== updatedContainer.id),
          updatedContainer,
        ]),
      ),
    );
    setContainerId(updatedContainer.id);
    setContainerSelectedElements(
      R.indexBy(
        R.prop('id'),
        (container.object_refs || [])
          .map((n) => indexedStixObjects[n] || null)
          .filter((n) => n !== null),
      ),
    );
    setContainerSelectAll(
      (container.object_refs || []).length
        >= Object.keys(indexedStixObjects).length,
    );
    setContainerStep(1);
    setStixDomainObjects(
      uniqWithByFields(
        ['name', 'type'],
        R.uniqBy(R.prop('id'), [
          ...stixDomainObjects,
          ...markingDefinitions,
          ...(identity ? [identity] : []),
        ]),
      ),
    );
  };
  const onSubmitContainerContext = () => {
    const container = R.head(containers.filter((n) => n.id === containerId)) || {};
    const indexedStixObjects = {
      ...R.indexBy(R.prop('id'), stixDomainObjects),
      ...R.indexBy(R.prop('id'), stixCyberObservables),
      ...R.indexBy(R.prop('id'), stixCoreRelationships),
    };
    let containerElementsIds = [];
    if (containerSelectAll) {
      containerElementsIds = R.uniq(
        R.values(indexedStixObjects)
          .filter(
            (n) => !Object.keys(containerDeselectedElements || {}).includes(n.id),
          )
          .map((n) => n.id),
      );
    } else {
      containerElementsIds = R.uniq(
        Object.keys(containerSelectedElements || {}),
      );
    }
    const updatedContainer = {
      ...container,
      object_refs: containerElementsIds,
    };
    setContainers(
      uniqWithByFields(
        ['name', 'type'],
        R.uniqBy(R.prop('id'), [
          ...containers.filter((n) => n.id !== updatedContainer.id),
          updatedContainer,
        ]),
      ),
    );
    setContainerId(null);
    setContainerType(null);
    setContainerSelectedElements(null);
    setContainerDeselectedElements(null);
    setContainerSelectAll(null);
    setContainerStep(0);
    handleCloseContainer();
  };
  // endregion

  // region converter
  const resolveMarkings = (objects, markingIds) => {
    if (markingIds) {
      return objects.filter((n) => markingIds.includes(n.id));
    }
    return [];
  };

  const convertCreatedByRef = (entity) => {
    if (entity && entity.created_by_ref) {
      const createdBy = findEntityById(entity.created_by_ref);
      if (createdBy) {
        return {
          label: createdBy.name,
          value: createdBy.id,
          entity: createdBy,
        };
      }
    }
    return '';
  };

  const convertLabels = (entity) => {
    if (entity && entity.labels) {
      return entity.labels.map((n) => ({ label: n, value: n }));
    }
    return [];
  };

  const convertExternalReferences = (entity) => {
    if (entity && entity.external_references) {
      return entity.external_references.map((n) => ({
        label: `[${n.source_name}] ${truncate(
          n.description || n.url || n.external_id,
          150,
        )}`,
        value: n.id,
        entity: n,
      }));
    }
    return [];
  };

  const convertMarkings = (entity) => {
    if (entity && entity.object_marking_refs) {
      return entity.object_marking_refs
        .map((n) => {
          const marking = findEntityById(n);
          if (marking) {
            return {
              label: marking.name || marking.definition,
              value: marking.id,
              entity: marking,
            };
          }
          return null;
        })
        .filter((n) => n !== null);
    }
    return [];
  };
  // endregion

  // region sorting
  const reverseBy = (field) => {
    setSortBy(field);
    setOrderAsc(!orderAsc);
  };
  const sortHeader = (field, label, isSortable) => {
    const sortComponent = orderAsc ? (
      <ArrowDropDown classes={{ root: classes.sortIcon }} style={{ top: 7 }} />
    ) : (
      <ArrowDropUp classes={{ root: classes.sortIcon }} style={{ top: 7 }} />
    );
    if (isSortable) {
      return (
        <div
          style={inlineStylesHeaders[field]}
          onClick={() => reverseBy(field)}
        >
          <span>{t(label)}</span>
          {sortBy === field ? sortComponent : ''}
        </div>
      );
    }
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t(label)}</span>
      </div>
    );
  };
  const containerReverseBy = (field) => {
    setContainerSortBy(field);
    setContainerOrderAsc(!containerOrderAsc);
  };
  const sortHeaderContainer = (field, label, isSortable) => {
    const sortComponent = containerOrderAsc ? (
      <ArrowDropDown classes={{ root: classes.sortIcon }} style={{ top: 7 }} />
    ) : (
      <ArrowDropUp classes={{ root: classes.sortIcon }} style={{ top: 7 }} />
    );
    if (isSortable) {
      return (
        <div
          style={inlineStylesHeaders[field]}
          onClick={() => containerReverseBy(field)}
        >
          <span>{t(label)}</span>
          {containerSortBy === field ? sortComponent : ''}
        </div>
      );
    }
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t(label)}</span>
      </div>
    );
  };
  // endregion

  // region render
  const renderEntityTypesList = () => {
    const subTypesEdges = stixDomainObjectTypes.edges;
    const sortByLabel = R.sortBy(R.compose(R.toLower, R.prop('tlabel')));
    const translatedOrderedList = R.pipe(
      R.map((n) => n.node),
      R.filter((n) => !typesContainers.includes(convertToStixType(n.label))),
      R.map((n) => R.assoc('tlabel', t(`entity_${n.label}`), n)),
      sortByLabel,
    )(subTypesEdges);
    return (
      <List>
        {translatedOrderedList.map((subType) => (
          <ListItem
            key={subType.label}
            divider
            button
            dense
            onClick={() => setEntityType(subType.label)}
          >
            <ListItemText primary={subType.tlabel} />
          </ListItem>
        ))}
      </List>
    );
  };

  const renderEntityForm = () => {
    const entity = R.head(stixDomainObjects.filter((n) => n.id === entityId)) || {};
    let type = entityType;
    if (type === 'Identity') {
      type = resolveIdentityType(entity.identity_class);
    } else if (type === 'Location') {
      type = resolveLocationType(entity);
    } else if (type === 'Threat-Actor') {
      type = resolveThreatActorType(entity);
    }
    return (
      <QueryRenderer
        query={workbenchFileContentAttributesQuery}
        variables={{ elementType: [type] }}
        render={({ props }) => {
          if (props && props.schemaAttributes) {
            const initialValues = {
              createdBy: convertCreatedByRef(entity),
              objectMarking: convertMarkings(entity),
              objectLabel: convertLabels(entity),
              externalReferences: convertExternalReferences(entity),
            };
            const attributes = R.filter(
              (n) => R.includes(
                n,
                R.map((o) => o.node.value, props.schemaAttributes.edges),
              ),
              workbenchAttributes,
            );
            for (const attribute of attributes) {
              if (R.includes(attribute, dateAttributes)) {
                initialValues[attribute] = entity[attribute]
                  ? buildDate(entity[attribute])
                  : now();
              } else if (R.includes(attribute, booleanAttributes)) {
                initialValues[attribute] = entity[attribute] || false;
              } else {
                initialValues[attribute] = entity[attribute] || '';
              }
            }
            return (
              <Formik
                initialValues={initialValues}
                onSubmit={onSubmitEntity}
                onReset={handleCloseEntity}
              >
                {({
                  submitForm,
                  handleReset,
                  isSubmitting,
                  setFieldValue,
                  values,
                }) => (
                  <Form
                    style={{ margin: '0 0 20px 0', padding: '0 15px 0 15px' }}
                  >
                    <div>
                      {attributes.map((attribute) => {
                        if (R.includes(attribute, dateAttributes)) {
                          return (
                            <Field
                              component={DateTimePickerField}
                              key={attribute}
                              name={attribute}
                              withSeconds
                              TextFieldProps={{
                                label: attribute,
                                variant: 'standard',
                                fullWidth: true,
                                style: { marginTop: 20 },
                              }}
                            />
                          );
                        }
                        if (R.includes(attribute, numberAttributes)) {
                          return (
                            <Field
                              component={TextField}
                              variant="standard"
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              fullWidth
                              type="number"
                              style={{ marginTop: 20 }}
                            />
                          );
                        }
                        if (R.includes(attribute, booleanAttributes)) {
                          return (
                            <Field
                              component={SwitchField}
                              type="checkbox"
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              containerstyle={{ marginTop: 20 }}
                            />
                          );
                        }
                        if (R.includes(attribute, markdownAttributes)) {
                          return (
                            <Field
                              component={MarkdownField}
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              fullWidth
                              multiline
                              rows="4"
                              style={{ marginTop: 20 }}
                            />
                          );
                        }
                        if (R.includes(attribute, htmlAttributes)) {
                          return (
                            <Field
                              component={RichTextField}
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              fullWidth
                              multiline
                              style={{ marginTop: 20, height: 150 }}
                            />
                          );
                        }
                        if (R.includes(attribute, vocabularyAttributes)) {
                          return (
                            <OpenVocabField
                              label={attribute}
                              name={attribute}
                              key={attribute}
                              fullWidth
                              containerStyle={{ marginTop: 20 }}
                              onChange={setFieldValue}
                              multiple={
                                getFieldDefinition(attribute)?.multiple ?? false
                              }
                              type={fieldToCategory(type, attribute)}
                            />
                          );
                        }
                        return (
                          <Field
                            component={TextField}
                            variant="standard"
                            key={attribute}
                            name={attribute}
                            label={attribute}
                            fullWidth
                            style={{ marginTop: 20 }}
                          />
                        );
                      })}
                    </div>
                    <CreatedByField
                      name="createdBy"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      dryrun
                    />
                    <ObjectLabelField
                      name="objectLabel"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      values={values.objectLabel}
                      dryrun
                    />
                    <ObjectMarkingField
                      name="objectMarking"
                      style={fieldSpacingContainerStyle}
                    />
                    <ExternalReferencesField
                      name="externalReferences"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      values={values.externalReferences}
                      dryrun
                    />
                    <div className={classes.buttons}>
                      <Button
                        variant="contained"
                        onClick={handleReset}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t('Cancel')}
                      </Button>
                      <Button
                        startIcon={<DoubleArrow />}
                        variant="contained"
                        color="secondary"
                        onClick={submitForm}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {entityId
                          ? t('Update and complete')
                          : t('Add and complete')}
                      </Button>
                    </div>
                  </Form>
                )}
              </Formik>
            );
          }
          return <div />;
        }}
      />
    );
  };

  const renderEntityContext = () => {
    const entity = R.head(stixDomainObjects.filter((n) => n.id === entityId)) || {};
    const indexedStixObjects = {
      ...R.indexBy(R.prop('id'), stixDomainObjects),
      ...R.indexBy(R.prop('id'), stixCyberObservables),
    };
    let type = entityType;
    if (type === 'Identity') {
      type = resolveIdentityType(entity.identity_class);
    } else if (type === 'Location') {
      type = resolveLocationType(entity);
    } else if (type === 'Threat-Actor') {
      type = resolveThreatActorType(entity);
    }
    const targetsFrom = [
      'Theat-Actor-Group',
      'Intrusion-Set',
      'Campaign',
      'Incident',
      'Malware',
      'Tool',
      'Channel',
    ];
    const usesFrom = [
      'Theat-Actor-Group',
      'Intrusion-Set',
      'Campaign',
      'Incident',
      'Malware',
      'Tool',
      'Channel',
    ];
    const attributedToFrom = [
      'Theat-Actor-Group',
      'Intrusion-Set',
      'Campaign',
      'Incident',
    ];
    const hasFrom = ['System'];
    const targetsTo = [
      'Sector',
      'Organization',
      'Individual',
      'System',
      'Region',
      'Country',
      'City',
      'Position',
      'Event',
    ];
    const attributedToTo = ['Theat-Actor-Group', 'Intrusion-Set', 'Campaign'];
    const usesTo = ['Attack-Pattern', 'Malware', 'Tool'];
    const initialValues = {};
    const resolveObjects = (relationshipType, source, target) => stixCoreRelationships
      .filter(
        (n) => n[source] === entity.id && n.relationship_type === relationshipType,
      )
      .map((n) => {
        const object = indexedStixObjects[n[target]];
        if (object) {
          let objectType = convertFromStixType(object.type);
          if (objectType === 'Identity') {
            objectType = resolveIdentityType(object.identity_class);
          } else if (objectType === 'Location') {
            objectType = resolveLocationType(object);
          } else if (type === 'Threat-Actor') {
            type = resolveThreatActorType(entity);
          }
          return {
            id: object.id,
            type: objectType,
            name: object.name,
          };
        }
        return {
          id: n[target],
          type: 'unknown',
          name: 'unknown',
        };
      });
    if (targetsFrom.includes(type)) {
      initialValues.targets_from = resolveObjects(
        'targets',
        'source_ref',
        'target_ref',
      );
    }
    if (usesFrom.includes(type)) {
      initialValues.uses_from = resolveObjects(
        'uses',
        'source_ref',
        'target_ref',
      );
    }
    if (attributedToFrom.includes(type)) {
      initialValues['attributed-to_from'] = resolveObjects(
        'attributed-to',
        'source_ref',
        'target_ref',
      );
    }
    if (hasFrom.includes(type)) {
      initialValues.has_from = resolveObjects(
        'attributed-to',
        'source_ref',
        'target_ref',
      );
    }
    if (targetsTo.includes(type)) {
      initialValues.targets_to = resolveObjects(
        'targets',
        'target_ref',
        'source_ref',
      );
    }
    if (attributedToTo.includes(type)) {
      initialValues['attributed-to_to'] = resolveObjects(
        'attributed-to',
        'target_ref',
        'source_ref',
      );
    }
    if (usesTo.includes(type)) {
      initialValues.uses_to = resolveObjects(
        'uses',
        'target_ref',
        'source_ref',
      );
    }
    return (
      <Formik
        initialValues={initialValues}
        onSubmit={onSubmitEntityContext}
        onReset={handleCloseEntity}
      >
        {({ submitForm, handleReset, isSubmitting }) => (
          <Form style={{ margin: '15px 0 20px 0', padding: '0 15px 0 15px' }}>
            {targetsFrom.includes(type) && (
              <Field
                component={DynamicResolutionField}
                variant="standard"
                name="targets_from"
                title={t('relationship_targets')}
                fullWidth
                types={[
                  'Sector',
                  'Organization',
                  'Individual',
                  'System',
                  'Region',
                  'Country',
                  'City',
                  'Position',
                  'Event',
                  'Vulnerability',
                ]}
                stixDomainObjects={stixDomainObjects}
              />
            )}
            {usesFrom.includes(type) && (
              <Field
                component={DynamicResolutionField}
                variant="standard"
                name="uses_from"
                title={t('relationship_uses')}
                fullWidth
                types={[
                  'Malware',
                  'Tool',
                  'Attack-Pattern',
                  'Infrastructure',
                  'Narrative',
                ]}
                stixDomainObjects={stixDomainObjects}
                style={{ marginTop: 20 }}
              />
            )}
            {attributedToFrom.includes(type) && (
              <Field
                component={DynamicResolutionField}
                variant="standard"
                name="attributed-to_from"
                title={t('relationship_attributed-to')}
                fullWidth
                types={['Theat-Actor-Group', 'Intrusion-Set', 'Campaign']}
                stixDomainObjects={stixDomainObjects}
                style={{ marginTop: 20 }}
              />
            )}
            {targetsTo.includes(type) && (
              <Field
                component={DynamicResolutionField}
                variant="standard"
                name="targets_to"
                title={t('relationship_targets')}
                fullWidth
                types={[
                  'Theat-Actor-Group',
                  'Intrusion-Set',
                  'Campaign',
                  'Incident',
                  'Malware',
                  'Tool',
                ]}
                stixDomainObjects={stixDomainObjects}
                style={{ marginTop: 20 }}
              />
            )}
            {attributedToTo.includes(type) && (
              <Field
                component={DynamicResolutionField}
                variant="standard"
                name="attributed-to_to"
                title={t('relationship_attributed-to') + t(' (reversed)')}
                fullWidth
                types={['Intrusion-Set', 'Campaign', 'Incident']}
                stixDomainObjects={stixDomainObjects}
                style={{ marginTop: 20 }}
              />
            )}
            {usesTo.includes(type) && (
              <Field
                component={DynamicResolutionField}
                variant="standard"
                name="uses_to"
                title={t('relationship_uses') + t(' (reversed)')}
                fullWidth
                types={[
                  'Theat-Actor-Group',
                  'Intrusion-Set',
                  'Campaign',
                  'Incident',
                  'Malware',
                ]}
                stixDomainObjects={stixDomainObjects}
                style={{ marginTop: 20 }}
              />
            )}
            <div className={classes.buttons}>
              <Button
                variant="contained"
                onClick={handleReset}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t('Cancel')}
              </Button>
              <Button
                variant="contained"
                color="secondary"
                onClick={() => submitForm(false)}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t('Add context')}
              </Button>
            </div>
          </Form>
        )}
      </Formik>
    );
  };

  const renderRelationshipForm = () => {
    const relationship = R.head(stixCoreRelationships.filter((n) => n.id === relationshipId))
      || {};
    return (
      <QueryRenderer
        query={workbenchFileContentAttributesQuery}
        variables={{ elementType: ['stix-core-relationship'] }}
        render={({ props }) => {
          if (props && props.schemaAttributes) {
            const initialValues = {
              createdBy: convertCreatedByRef(relationship),
              objectMarking: convertMarkings(relationship),
              objectLabel: convertLabels(relationship),
              externalReferences: convertExternalReferences(relationship),
            };
            const attributes = R.filter(
              (n) => R.includes(
                n,
                R.map((o) => o.node.value, props.schemaAttributes.edges),
              ),
              workbenchAttributes,
            );
            for (const attribute of attributes) {
              if (R.includes(attribute, dateAttributes)) {
                initialValues[attribute] = relationship[attribute]
                  ? buildDate(relationship[attribute])
                  : now();
              } else if (R.includes(attribute, booleanAttributes)) {
                initialValues[attribute] = relationship[attribute] || false;
              } else {
                initialValues[attribute] = relationship[attribute] || '';
              }
            }
            return (
              <Formik
                initialValues={initialValues}
                onSubmit={onSubmitRelationship}
                onReset={handleCloseRelationship}
              >
                {({
                  submitForm,
                  handleReset,
                  isSubmitting,
                  setFieldValue,
                  values,
                }) => (
                  <Form
                    style={{ margin: '0 0 20px 0', padding: '0 15px 0 15px' }}
                  >
                    <div>
                      {attributes.map((attribute) => {
                        if (R.includes(attribute, dateAttributes)) {
                          return (
                            <Field
                              component={DateTimePickerField}
                              key={attribute}
                              name={attribute}
                              withSeconds={true}
                              TextFieldProps={{
                                label: attribute,
                                variant: 'standard',
                                fullWidth: true,
                                style: { marginTop: 20 },
                              }}
                            />
                          );
                        }
                        if (R.includes(attribute, numberAttributes)) {
                          return (
                            <Field
                              component={TextField}
                              variant="standard"
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              fullWidth={true}
                              type="number"
                              style={{ marginTop: 20 }}
                            />
                          );
                        }
                        if (R.includes(attribute, booleanAttributes)) {
                          return (
                            <Field
                              component={SwitchField}
                              type="checkbox"
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              containerstyle={{ marginTop: 20 }}
                            />
                          );
                        }
                        if (R.includes(attribute, markdownAttributes)) {
                          return (
                            <Field
                              component={MarkdownField}
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              fullWidth={true}
                              multiline={true}
                              rows="4"
                              style={{ marginTop: 20 }}
                            />
                          );
                        }
                        if (R.includes(attribute, htmlAttributes)) {
                          return (
                            <Field
                              component={RichTextField}
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              fullWidth={true}
                              multiline={true}
                              style={{ marginTop: 20, height: 150 }}
                            />
                          );
                        }
                        return (
                          <Field
                            component={TextField}
                            variant="standard"
                            key={attribute}
                            name={attribute}
                            label={attribute}
                            fullWidth={true}
                            style={{ marginTop: 20 }}
                          />
                        );
                      })}
                    </div>
                    <CreatedByField
                      name="createdBy"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                    />
                    <ObjectLabelField
                      name="objectLabel"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      values={values.objectLabel}
                    />
                    <ObjectMarkingField
                      name="objectMarking"
                      style={fieldSpacingContainerStyle}
                    />
                    <ExternalReferencesField
                      name="externalReferences"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      values={values.externalReferences}
                    />
                    <div className={classes.buttons}>
                      <Button
                        variant="contained"
                        onClick={handleReset}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t('Cancel')}
                      </Button>
                      <Button
                        variant="contained"
                        color="secondary"
                        onClick={submitForm}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t('Update')}
                      </Button>
                    </div>
                  </Form>
                )}
              </Formik>
            );
          }
          return <div />;
        }}
      />
    );
  };

  const renderObservableTypesList = () => {
    const subTypesEdges = observableTypes.edges;
    const sortByLabel = R.sortBy(R.compose(R.toLower, R.prop('tlabel')));
    const translatedOrderedList = R.pipe(
      R.map((n) => n.node),
      R.filter((n) => !typesContainers.includes(convertToStixType(n.label))),
      R.map((n) => R.assoc('tlabel', t(`entity_${n.label}`), n)),
      sortByLabel,
    )(subTypesEdges);
    return (
      <List>
        {translatedOrderedList.map((subType) => (
          <ListItem
            key={subType.label}
            divider
            button
            dense
            onClick={() => setObservableType(subType.label)}
          >
            <ListItemText primary={subType.tlabel} />
          </ListItem>
        ))}
      </List>
    );
  };

  const renderObservableForm = () => {
    const observable = R.head(stixCyberObservables.filter((n) => n.id === observableId)) || {};
    return (
      <QueryRenderer
        query={workbenchFileContentAttributesQuery}
        variables={{ elementType: [observableType] }}
        render={({ props }) => {
          if (props && props.schemaAttributes) {
            const initialValues = {
              createdBy: convertCreatedByRef(observable),
              objectMarking: convertMarkings(observable),
              objectLabel: convertLabels(observable),
              externalReferences: convertExternalReferences(observable),
            };
            const attributes = R.pipe(
              R.map((n) => n.node.value),
              R.filter(
                (n) => !R.includes(n, ignoredAttributes) && !n.startsWith('i_'),
              ),
            )(props.schemaAttributes.edges);
            for (const attribute of attributes) {
              if (R.includes(attribute, dateAttributes)) {
                initialValues[attribute] = observable[attribute]
                  ? buildDate(observable[attribute])
                  : null;
              } else if (R.includes(attribute, booleanAttributes)) {
                initialValues[attribute] = observable[attribute] ?? false;
              } else if (R.includes(attribute, multipleAttributes)) {
                initialValues[attribute] = Array.isArray(observable[attribute])
                  ? observable[attribute].join(',')
                  : observable[attribute];
              } else if (attribute === 'hashes') {
                initialValues.hashes_MD5 = observable[attribute]
                  ? observable[attribute].MD5 ?? ''
                  : '';
                initialValues['hashes_SHA-1'] = observable[attribute]
                  ? observable[attribute]['SHA-1'] ?? ''
                  : '';
                initialValues['hashes_SHA-256'] = observable[attribute]
                  ? observable[attribute]['SHA-256'] ?? ''
                  : '';
                initialValues['hashes_SHA-512'] = observable[attribute]
                  ? observable[attribute]['SGA-512'] ?? ''
                  : '';
              } else {
                initialValues[attribute] = observable[attribute] ?? '';
              }
            }
            return (
              <Formik
                initialValues={initialValues}
                onSubmit={onSubmitObservable}
                onReset={handleCloseObservable}
              >
                {({
                  submitForm,
                  handleReset,
                  isSubmitting,
                  setFieldValue,
                  values,
                }) => (
                  <Form
                    style={{ margin: '0 0 20px 0', padding: '0 15px 0 15px' }}
                  >
                    <div>
                      {attributes.map((attribute) => {
                        if (R.includes(attribute, dateAttributes)) {
                          return (
                            <Field
                              component={DateTimePickerField}
                              key={attribute}
                              name={attribute}
                              withSeconds
                              TextFieldProps={{
                                label: attribute,
                                variant: 'standard',
                                fullWidth: true,
                                style: { marginTop: 20 },
                              }}
                            />
                          );
                        }
                        if (attribute === 'hashes') {
                          return (
                            <div key={attribute}>
                              <Field
                                component={TextField}
                                variant="standard"
                                name="hashes_MD5"
                                label={t('hash_md5')}
                                fullWidth
                                style={{ marginTop: 20 }}
                              />
                              <Field
                                component={TextField}
                                variant="standard"
                                name="hashes_SHA-1"
                                label={t('hash_sha-1')}
                                fullWidth
                                style={{ marginTop: 20 }}
                              />
                              <Field
                                component={TextField}
                                variant="standard"
                                name="hashes_SHA-256"
                                label={t('hash_sha-256')}
                                fullWidth
                                style={{ marginTop: 20 }}
                              />
                              <Field
                                component={TextField}
                                variant="standard"
                                name="hashes.SHA-512"
                                label={t('hash_sha-512')}
                                fullWidth
                                style={{ marginTop: 20 }}
                              />
                            </div>
                          );
                        }
                        if (R.includes(attribute, numberAttributes)) {
                          return (
                            <Field
                              component={TextField}
                              variant="standard"
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              fullWidth
                              type="number"
                              style={{ marginTop: 20 }}
                            />
                          );
                        }
                        if (R.includes(attribute, booleanAttributes)) {
                          return (
                            <Field
                              component={SwitchField}
                              type="checkbox"
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              containerstyle={{ marginTop: 20 }}
                            />
                          );
                        }
                        if (R.includes(attribute, markdownAttributes)) {
                          return (
                            <Field
                              component={MarkdownField}
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              fullWidth
                              multiline
                              rows="4"
                              style={{ marginTop: 20 }}
                            />
                          );
                        }
                        if (R.includes(attribute, htmlAttributes)) {
                          return (
                            <Field
                              component={RichTextField}
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              fullWidth
                              multiline
                              style={{ marginTop: 20, height: 150 }}
                            />
                          );
                        }
                        if (R.includes(attribute, vocabularyAttributes)) {
                          return (
                            <OpenVocabField
                              label={attribute}
                              name={attribute}
                              key={attribute}
                              fullWidth
                              containerStyle={{ marginTop: 20 }}
                              onChange={setFieldValue}
                              multiple={
                                getFieldDefinition(attribute)?.multiple ?? false
                              }
                              type={fieldToCategory(observableType, attribute)}
                            />
                          );
                        }
                        return (
                          <Field
                            component={TextField}
                            variant="standard"
                            key={attribute}
                            name={attribute}
                            label={attribute}
                            fullWidth
                            style={{ marginTop: 20 }}
                          />
                        );
                      })}
                    </div>
                    <CreatedByField
                      name="createdBy"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                    />
                    <ObjectLabelField
                      name="objectLabel"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      values={values.objectLabel}
                    />
                    <ObjectMarkingField
                      name="objectMarking"
                      style={fieldSpacingContainerStyle}
                    />
                    <ExternalReferencesField
                      name="externalReferences"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      values={values.externalReferences}
                    />
                    <div className={classes.buttons}>
                      <Button
                        variant="contained"
                        onClick={handleReset}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t('Cancel')}
                      </Button>
                      <Button
                        variant="contained"
                        color="secondary"
                        onClick={submitForm}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {observableId ? t('Update') : t('Add')}
                      </Button>
                    </div>
                  </Form>
                )}
              </Formik>
            );
          }
          return <div />;
        }}
      />
    );
  };

  const renderContainerForm = () => {
    const container = R.head(containers.filter((n) => n.id === containerId)) || {};
    return (
      <QueryRenderer
        query={workbenchFileContentAttributesQuery}
        variables={{ elementType: [containerType] }}
        render={({ props }) => {
          if (props && props.schemaAttributes) {
            const initialValues = {
              createdBy: convertCreatedByRef(container),
              objectMarking: convertMarkings(container),
              objectLabel: convertLabels(container),
              externalReferences: convertExternalReferences(container),
            };
            const attributes = R.filter(
              (n) => R.includes(
                n,
                R.map((o) => o.node.value, props.schemaAttributes.edges),
              ),
              workbenchAttributes,
            );
            for (const attribute of attributes) {
              if (R.includes(attribute, dateAttributes)) {
                initialValues[attribute] = container[attribute]
                  ? buildDate(container[attribute])
                  : now();
              } else if (R.includes(attribute, booleanAttributes)) {
                initialValues[attribute] = container[attribute] || false;
              } else {
                initialValues[attribute] = container[attribute] || '';
              }
            }
            return (
              <Formik
                initialValues={initialValues}
                onSubmit={onSubmitContainer}
                onReset={handleCloseContainer}
              >
                {({
                  submitForm,
                  handleReset,
                  isSubmitting,
                  setFieldValue,
                  values,
                }) => (
                  <Form
                    style={{ margin: '0 0 20px 0', padding: '0 15px 0 15px' }}
                  >
                    <div>
                      {attributes.map((attribute) => {
                        if (R.includes(attribute, dateAttributes)) {
                          return (
                            <Field
                              component={DateTimePickerField}
                              key={attribute}
                              name={attribute}
                              withSeconds
                              TextFieldProps={{
                                label: attribute,
                                variant: 'standard',
                                fullWidth: true,
                                style: { marginTop: 20 },
                              }}
                            />
                          );
                        }
                        if (R.includes(attribute, numberAttributes)) {
                          return (
                            <Field
                              component={TextField}
                              variant="standard"
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              fullWidth
                              type="number"
                              style={{ marginTop: 20 }}
                            />
                          );
                        }
                        if (R.includes(attribute, booleanAttributes)) {
                          return (
                            <Field
                              component={SwitchField}
                              type="checkbox"
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              containerstyle={{ marginTop: 20 }}
                            />
                          );
                        }
                        if (R.includes(attribute, markdownAttributes)) {
                          return (
                            <Field
                              component={MarkdownField}
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              fullWidth
                              multiline
                              rows="4"
                              style={{ marginTop: 20 }}
                            />
                          );
                        }
                        if (R.includes(attribute, htmlAttributes)) {
                          return (
                            <Field
                              component={RichTextField}
                              key={attribute}
                              name={attribute}
                              label={attribute}
                              fullWidth
                              multiline
                              style={{ marginTop: 20, height: 150 }}
                            />
                          );
                        }
                        if (R.includes(attribute, vocabularyAttributes)) {
                          return (
                            <OpenVocabField
                              label={attribute}
                              name={attribute}
                              key={attribute}
                              fullWidth
                              containerStyle={{ marginTop: 20 }}
                              onChange={setFieldValue}
                              multiple={
                                getFieldDefinition(attribute)?.multiple ?? false
                              }
                              type={fieldToCategory(containerType, attribute)}
                            />
                          );
                        }
                        return (
                          <Field
                            component={TextField}
                            variant="standard"
                            key={attribute}
                            name={attribute}
                            label={attribute}
                            fullWidth
                            style={{ marginTop: 20 }}
                          />
                        );
                      })}
                    </div>
                    <CreatedByField
                      name="createdBy"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                    />
                    <ObjectLabelField
                      name="objectLabel"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      values={values.objectLabel}
                    />
                    <ObjectMarkingField
                      name="objectMarking"
                      style={fieldSpacingContainerStyle}
                    />
                    <ExternalReferencesField
                      name="externalReferences"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      values={values.externalReferences}
                    />
                    <div className={classes.buttons}>
                      <Button
                        variant="contained"
                        onClick={handleReset}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t('Cancel')}
                      </Button>
                      <Button
                        startIcon={<DoubleArrow />}
                        variant="contained"
                        color="secondary"
                        onClick={submitForm}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {containerId
                          ? t('Update and complete')
                          : t('Add and complete')}
                      </Button>
                    </div>
                  </Form>
                )}
              </Formik>
            );
          }
          return <div />;
        }}
      />
    );
  };

  const renderContainerContext = () => {
    const indexedStixObjects = {
      ...R.indexBy(R.prop('id'), stixDomainObjects),
      ...R.indexBy(R.prop('id'), stixCyberObservables),
      ...R.indexBy(R.prop('id'), stixCoreRelationships),
    };
    const resolvedObjects = R.values(indexedStixObjects).map((n) => ({
      ...n,
      ttype:
        n.type === 'relationship'
          ? t(`relationship_${n.relationship_type}`)
          : t(`entity_${convertFromStixType(n.type)}`),
      default_value: defaultValue({
        ...n,
        source_ref_name: defaultValue(indexedStixObjects[n.source_ref] || {}),
        target_ref_name: defaultValue(indexedStixObjects[n.target_ref] || {}),
      }),
      markings: resolveMarkings(stixDomainObjects, n.object_marking_refs),
    }));
    const sort = R.sortWith(
      containerOrderAsc
        ? [R.ascend(R.prop(containerSortBy))]
        : [R.descend(R.prop(containerSortBy))],
    );
    const sortedObjects = sort(
      resolvedObjects.filter((n) => n.type !== 'marking-definition'),
    );
    return (
      <div style={{ padding: '0 15px 0 15px' }}>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem
            classes={{ root: classes.itemHead }}
            divider={false}
            style={{ paddingTop: 0 }}
          >
            <ListItemIcon
              style={{
                minWidth: 38,
              }}
              onClick={handleToggleContainerSelectAll}
            >
              <Checkbox
                edge="start"
                checked={containerSelectAll}
                disableRipple
              />
            </ListItemIcon>
            <ListItemIcon>
              <span
                style={{
                  padding: '0 8px 0 8px',
                  fontWeight: 700,
                  fontSize: 12,
                }}
              >
                &nbsp;
              </span>
            </ListItemIcon>
            <ListItemText
              primary={
                <div>
                  {sortHeaderContainer('ttype', 'Type', true)}
                  {sortHeaderContainer('default_value', 'Default value', true)}
                  {sortHeaderContainer('labels', 'Labels', true)}
                  {sortHeaderContainer('markings', 'Marking definitions', true)}
                </div>
              }
            />
          </ListItem>
          {sortedObjects.map((object) => {
            const type = convertFromStixType(object.type);
            let secondaryType = '';
            if (type === 'Identity') {
              secondaryType = ` (${t(
                `entity_${resolveIdentityType(object.identity_class)}`,
              )})`;
            }
            if (type === 'Location') {
              secondaryType = ` (${t(
                `entity_${resolveLocationType(object)}`,
              )})`;
            }
            if (type === 'Threat-Actor') {
              secondaryType = ` (${t(
                `entity_${resolveThreatActorType(object)}`,
              )})`;
            }
            return (
              <ListItem
                key={object.id}
                classes={{ root: classes.item }}
                divider
                button
                onClick={(event) => handleToggleContainerSelectObject(object, event)
                }
              >
                <ListItemIcon
                  classes={{ root: classes.itemIcon }}
                  style={{ minWidth: 40 }}
                >
                  <Checkbox
                    edge="start"
                    checked={
                      (containerSelectAll
                        && !(object.id in (containerDeselectedElements || {})))
                      || object.id in (containerSelectedElements || {})
                    }
                    disableRipple
                  />
                </ListItemIcon>
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <ItemIcon type={type} />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.ttype}
                      >
                        {object.ttype}
                        {secondaryType}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.default_value}
                      >
                        {object.default_value}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.labels}
                      >
                        <StixItemLabels
                          variant="inList"
                          labels={object.labels || []}
                        />
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.markings}
                      >
                        <StixItemMarkings
                          variant="inList"
                          markingDefinitions={object.markings || []}
                          limit={2}
                        />
                      </div>
                    </div>
                  }
                />
              </ListItem>
            );
          })}
        </List>
        <div className={classes.buttons}>
          <Button
            variant="contained"
            onClick={handleCloseContainer}
            classes={{ root: classes.button }}
          >
            {t('Cancel')}
          </Button>
          <Button
            variant="contained"
            color="secondary"
            onClick={onSubmitContainerContext}
            classes={{ root: classes.button }}
          >
            {t('Update context')}
          </Button>
        </div>
      </div>
    );
  };

  const renderEntities = () => {
    const resolvedStixDomainObjects = stixDomainObjects.map((n) => ({
      ...n,
      ttype: t(`entity_${convertFromStixType(n.type)}`),
      default_value: defaultValue(n),
      markings: resolveMarkings(stixDomainObjects, n.object_marking_refs),
    }));
    const sort = R.sortWith(
      orderAsc ? [R.ascend(R.prop(sortBy))] : [R.descend(R.prop(sortBy))],
    );
    const sortedStixDomainObjects = sort(resolvedStixDomainObjects);
    return (
      <div>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem
            classes={{ root: classes.itemHead }}
            divider={false}
            style={{ paddingTop: 0 }}
          >
            <ListItemIcon
              style={{
                minWidth: 38,
              }}
              onClick={handleToggleSelectAll}
            >
              <Checkbox edge="start" checked={selectAll} disableRipple={true} />
            </ListItemIcon>
            <ListItemIcon>
              <span
                style={{
                  padding: '0 8px 0 8px',
                  fontWeight: 700,
                  fontSize: 12,
                }}
              >
                &nbsp;
              </span>
            </ListItemIcon>
            <ListItemText
              primary={
                <div>
                  {sortHeader('ttype', 'Type', true)}
                  {sortHeader('default_value', 'Default value', true)}
                  {sortHeader('labels', 'Labels', true)}
                  {sortHeader('markings', 'Marking definitions', true)}
                  {sortHeader('in_platform', 'Already in plat.', true)}
                </div>
              }
            />
            <ListItemSecondaryAction>&nbsp;</ListItemSecondaryAction>
          </ListItem>
          {sortedStixDomainObjects.map((object) => {
            const type = convertFromStixType(object.type);
            let secondaryType = '';
            if (type === 'Identity') {
              secondaryType = ` (${t(
                `entity_${resolveIdentityType(object.identity_class)}`,
              )})`;
            }
            if (type === 'Location') {
              secondaryType = ` (${t(
                `entity_${resolveLocationType(object)}`,
              )})`;
            }
            if (type === 'Threat-Actor') {
              secondaryType = ` (${t(
                `entity_${resolveThreatActorType(object)}`,
              )})`;
            }
            return (
              <ListItem
                key={object.id}
                classes={{ root: classes.item }}
                divider={true}
                button={object.type !== 'marking-definition'}
                onClick={
                  object.type === 'marking-definition'
                    ? null
                    : () => handleOpenEntity(object.type, object.id)
                }
              >
                <ListItemIcon
                  classes={{ root: classes.itemIcon }}
                  style={{ minWidth: 40 }}
                  onClick={(event) => handleToggleSelectObject(object, event)}
                >
                  <Checkbox
                    edge="start"
                    checked={
                      (selectAll
                        && !(object.id in (deSelectedElements || {})))
                      || object.id in (selectedElements || {})
                    }
                    disableRipple
                  />
                </ListItemIcon>
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <ItemIcon type={type} />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.ttype}
                      >
                        {object.ttype}
                        {secondaryType}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.default_value}
                      >
                        {object.default_value || t('Unknown')}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.labels}
                      >
                        <StixItemLabels
                          variant="inList"
                          labels={object.labels || []}
                        />
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.markings}
                      >
                        <StixItemMarkings
                          variant="inList"
                          markingDefinitions={object.markings || []}
                          limit={2}
                        />
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.in_platform}
                      >
                        {object.default_value
                        && object.type !== 'marking-definition' ? (
                          <QueryRenderer
                            query={stixDomainObjectsLinesSearchQuery}
                            variables={{
                              types: [type],
                              filters: [
                                {
                                  key: [
                                    'name',
                                    'aliases',
                                    'x_opencti_aliases',
                                    'x_mitre_id',
                                  ],
                                  values:
                                    object.name
                                    || object.value
                                    || object.definition,
                                },
                              ],
                              count: 1,
                            }}
                            render={({ props }) => {
                              if (props && props.stixDomainObjects) {
                                return props.stixDomainObjects.edges.length
                                  > 0 ? (
                                  <ItemBoolean
                                    variant="inList"
                                    status={true}
                                    label={t('Yes')}
                                  />
                                  ) : (
                                  <ItemBoolean
                                    variant="inList"
                                    status={false}
                                    label={t('No')}
                                  />
                                  );
                              }
                              return (
                                <ItemBoolean
                                  variant="inList"
                                  status={undefined}
                                  label={t('Pending')}
                                />
                              );
                            }}
                          />
                          ) : (
                          <ItemBoolean
                            variant="inList"
                            status={null}
                            label={t('Not applicable')}
                          />
                          )}
                      </div>
                    </div>
                  }
                />
                <ListItemSecondaryAction>
                  <IconButton
                    onClick={() => handleDeleteObject(object)}
                    aria-haspopup="true"
                  >
                    <DeleteOutlined />
                  </IconButton>
                </ListItemSecondaryAction>
              </ListItem>
            );
          })}
        </List>
        <Fab
          onClick={() => handleOpenEntity(null, null)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Drawer
          open={entityStep != null}
          anchor="right"
          sx={{ zIndex: 1202 }}
          elevation={1}
          classes={{ paper: classes.drawerPaper }}
          onClose={handleCloseEntity}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={handleCloseEntity}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t('Manage an entity')}</Typography>
          </div>
          <div className={classes.container}>
            {!entityType && renderEntityTypesList()}
            {entityType && entityStep === 0 && renderEntityForm()}
            {entityType && entityStep === 1 && renderEntityContext()}
          </div>
        </Drawer>
      </div>
    );
  };

  const renderObservables = () => {
    const subTypesEdges = observableTypes.edges;
    const sortByLabel = R.sortBy(R.compose(R.toLower, R.prop('tlabel')));
    const translatedOrderedList = R.pipe(
      R.map((n) => n.node),
      R.filter((n) => !typesContainers.includes(convertToStixType(n.label))),
      R.map((n) => R.assoc('tlabel', t(`entity_${n.label}`), n)),
      sortByLabel,
    )(subTypesEdges);
    const resolvedStixCyberObservables = stixCyberObservables.map((n) => ({
      ...n,
      ttype: t(`entity_${convertFromStixType(n.type)}`),
      default_value: defaultValue(n),
      markings: resolveMarkings(stixDomainObjects, n.object_marking_refs),
    }));
    const sort = R.sortWith(
      orderAsc ? [R.ascend(R.prop(sortBy))] : [R.descend(R.prop(sortBy))],
    );
    const sortedStixCyberObservables = sort(resolvedStixCyberObservables);
    return (
      <div>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem
            classes={{ root: classes.itemHead }}
            divider={false}
            style={{ paddingTop: 0 }}
          >
            <ListItemIcon
              style={{
                minWidth: 38,
              }}
              onClick={handleToggleSelectAll}
            >
              <Checkbox edge="start" checked={selectAll} disableRipple />
            </ListItemIcon>
            <ListItemIcon>
              <span
                style={{
                  padding: '0 8px 0 8px',
                  fontWeight: 700,
                  fontSize: 12,
                }}
              >
                &nbsp;
              </span>
            </ListItemIcon>
            <ListItemText
              primary={
                <div>
                  {sortHeader('ttype', 'Type', true)}
                  {sortHeader('default_value', 'Default value', true)}
                  {sortHeader('labels', 'Labels', true)}
                  {sortHeader('markings', 'Marking definitions', true)}
                  {sortHeader('in_platform', 'Already in plat.', true)}
                </div>
              }
            />
            <ListItemSecondaryAction>&nbsp;</ListItemSecondaryAction>
          </ListItem>
          {sortedStixCyberObservables.map((object) => {
            const type = convertFromStixType(object.type);
            return (
              <ListItem
                key={object.id}
                classes={{ root: classes.item }}
                divider
                button={object.type !== 'marking-definition'}
                onClick={
                  object.type === 'marking-definition'
                    ? null
                    : () => handleOpenObservable(object.type, object.id)
                }
              >
                <ListItemIcon
                  classes={{ root: classes.itemIcon }}
                  style={{ minWidth: 40 }}
                  onClick={(event) => handleToggleSelectObject(object, event)}
                >
                  <Checkbox
                    edge="start"
                    checked={
                      (selectAll
                        && !(object.id in (deSelectedElements || {})))
                      || object.id in (selectedElements || {})
                    }
                    disableRipple
                  />
                </ListItemIcon>
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <ItemIcon type={type} />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.ttype}
                      >
                        <Select
                          variant="standard"
                          labelId="type"
                          value={convertFromStixType(object.type)}
                          onChange={(event) => handleChangeObservableType(object.id, event)
                          }
                          style={{
                            margin: 0,
                            width: '80%',
                            height: '100%',
                          }}
                          onClick={(event) => {
                            event.stopPropagation();
                            event.preventDefault();
                          }}
                        >
                          {translatedOrderedList.map((n) => (
                            <MenuItem key={n.label} value={n.label}>
                              {n.tlabel}
                            </MenuItem>
                          ))}
                        </Select>
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.default_value}
                      >
                        {object.default_value || t('Unknown')}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.labels}
                      >
                        <StixItemLabels
                          variant="inList"
                          labels={object.labels || []}
                        />
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.markings}
                      >
                        <StixItemMarkings
                          variant="inList"
                          markingDefinitions={object.markings || []}
                          limit={2}
                        />
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.in_platform}
                      >
                        {object.default_value
                        && object.type !== 'marking-definition' ? (
                          <QueryRenderer
                            query={stixCyberObservablesLinesSearchQuery}
                            variables={{
                              types: [type],
                              filters: [
                                {
                                  key: [
                                    'name',
                                    'value',
                                    'hashes_MD5',
                                    'hashes_SHA1',
                                    'hashes_SHA256',
                                  ],
                                  values: [object.default_value],
                                },
                              ],
                              count: 1,
                            }}
                            render={({ props }) => {
                              if (props && props.stixCyberObservables) {
                                return props.stixCyberObservables.edges.length
                                  > 0 ? (
                                  <ItemBoolean
                                    variant="inList"
                                    status={true}
                                    label={t('Yes')}
                                  />
                                  ) : (
                                  <ItemBoolean
                                    variant="inList"
                                    status={false}
                                    label={t('No')}
                                  />
                                  );
                              }
                              return (
                                <ItemBoolean
                                  variant="inList"
                                  status={undefined}
                                  label={t('Pending')}
                                />
                              );
                            }}
                          />
                          ) : (
                          <ItemBoolean
                            variant="inList"
                            status={null}
                            label={t('Not applicable')}
                          />
                          )}
                      </div>
                    </div>
                  }
                />
                <ListItemSecondaryAction>
                  <IconButton
                    onClick={() => handleDeleteObject(object)}
                    aria-haspopup="true"
                  >
                    <DeleteOutlined />
                  </IconButton>
                </ListItemSecondaryAction>
              </ListItem>
            );
          })}
        </List>
        <Fab
          onClick={() => handleOpenObservable(null, null)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Drawer
          open={displayObservable}
          anchor="right"
          sx={{ zIndex: 1202 }}
          elevation={1}
          classes={{ paper: classes.drawerPaper }}
          onClose={handleCloseObservable}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={handleCloseObservable}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t('Manage an observable')}</Typography>
          </div>
          <div className={classes.container}>
            {!observableType && renderObservableTypesList()}
            {observableType && renderObservableForm()}
          </div>
        </Drawer>
      </div>
    );
  };

  const renderRelationships = () => {
    const indexedStixObjects = {
      ...R.indexBy(R.prop('id'), stixDomainObjects),
      ...R.indexBy(R.prop('id'), stixCyberObservables),
    };
    const resolvedStixCoreRelationships = stixCoreRelationships.map((n) => ({
      ...n,
      ttype: t(`relationship_${n.relationship_type}`),
      default_value: defaultValue({
        ...n,
        source_ref_name: defaultValue(indexedStixObjects[n.source_ref] || {}),
        target_ref_name: defaultValue(indexedStixObjects[n.target_ref] || {}),
      }),
      source_ref_name: defaultValue(indexedStixObjects[n.source_ref] || {}),
      target_ref_name: defaultValue(indexedStixObjects[n.target_ref] || {}),
      markings: resolveMarkings(stixDomainObjects, n.object_marking_refs),
    }));
    const sort = R.sortWith(
      orderAsc ? [R.ascend(R.prop(sortBy))] : [R.descend(R.prop(sortBy))],
    );
    const sortedStixCoreRelationships = sort(resolvedStixCoreRelationships);
    return (
      <div>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem
            classes={{ root: classes.itemHead }}
            divider={false}
            style={{ paddingTop: 0 }}
          >
            <ListItemIcon
              style={{
                minWidth: 38,
              }}
              onClick={handleToggleSelectAll}
            >
              <Checkbox edge="start" checked={selectAll} disableRipple={true} />
            </ListItemIcon>
            <ListItemIcon>
              <span
                style={{
                  padding: '0 8px 0 8px',
                  fontWeight: 700,
                  fontSize: 12,
                }}
              >
                &nbsp;
              </span>
            </ListItemIcon>
            <ListItemText
              primary={
                <div>
                  {sortHeader('ttype', 'Type', true)}
                  {sortHeader('default_value', 'Default value', true)}
                  {sortHeader('labels', 'Labels', true)}
                  {sortHeader('markings', 'Marking definitions', true)}
                </div>
              }
            />
            <ListItemSecondaryAction>&nbsp;</ListItemSecondaryAction>
          </ListItem>
          {sortedStixCoreRelationships.map((object) => (
            <ListItem
              key={object.id}
              classes={{ root: classes.item }}
              divider
              button
              onClick={() => handleOpenRelationship(object.id)}
            >
              <ListItemIcon
                classes={{ root: classes.itemIcon }}
                style={{ minWidth: 40 }}
                onClick={(event) => handleToggleSelectObject(object, event)}
              >
                <Checkbox
                  edge="start"
                  checked={
                    (selectAll && !(object.id in (deSelectedElements || {})))
                    || object.id in (selectedElements || {})
                  }
                  disableRipple
                />
              </ListItemIcon>
              <ListItemIcon classes={{ root: classes.itemIcon }}>
                <ItemIcon type={object.relationship_type} />
              </ListItemIcon>
              <ListItemText
                primary={
                  <div>
                    <div
                      className={classes.bodyItem}
                      style={inlineStyles.ttype}
                    >
                      {object.ttype}
                    </div>
                    <div
                      className={classes.bodyItem}
                      style={inlineStyles.default_value}
                    >
                      {object.default_value || t('Unknown')}
                    </div>
                    <div
                      className={classes.bodyItem}
                      style={inlineStyles.labels}
                    >
                      <StixItemLabels
                        variant="inList"
                        labels={object.labels || []}
                      />
                    </div>
                    <div
                      className={classes.bodyItem}
                      style={inlineStyles.markings}
                    >
                      <StixItemMarkings
                        variant="inList"
                        markingDefinitions={object.markings || []}
                        limit={2}
                      />
                    </div>
                  </div>
                }
              />
              <ListItemSecondaryAction>
                <IconButton
                  onClick={() => handleDeleteObject(object)}
                  aria-haspopup="true"
                >
                  <DeleteOutlined />
                </IconButton>
              </ListItemSecondaryAction>
            </ListItem>
          ))}
        </List>
        <Drawer
          open={relationshipId}
          anchor="right"
          sx={{ zIndex: 1202 }}
          elevation={1}
          classes={{ paper: classes.drawerPaper }}
          onClose={handleCloseRelationship}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={handleCloseRelationship}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t('Manage a relationship')}</Typography>
          </div>
          <div className={classes.container}>
            {relationshipId && renderRelationshipForm()}
          </div>
        </Drawer>
      </div>
    );
  };

  const renderContainerTypesList = () => {
    const subTypesEdges = stixDomainObjectTypes.edges;
    const sortByLabel = R.sortBy(R.compose(R.toLower, R.prop('tlabel')));
    const translatedOrderedList = R.pipe(
      R.map((n) => n.node),
      R.filter((n) => [
        'report',
        'note',
        'grouping',
        'x-opencti-feedback',
        'feedback',
        'x-opencti-case-incident',
        'case-incident',
        'x-opencti-case-rfi',
        'case-rfi',
        'case-rft',
        'x-opencti-case-rft',
        'task',
        'x-opencti-task',
      ].includes(convertToStixType(n.label))),
      R.map((n) => R.assoc('tlabel', t(`entity_${n.label}`), n)),
      sortByLabel,
    )(subTypesEdges);
    return (
      <List>
        {translatedOrderedList.map((subType) => (
          <ListItem
            key={subType.label}
            divider
            button
            dense
            onClick={() => setContainerType(subType.label)}
          >
            <ListItemText primary={subType.tlabel} />
          </ListItem>
        ))}
      </List>
    );
  };

  const renderContainers = () => {
    const resolvedContainers = containers.map((n) => ({
      ...n,
      ttype: t(`entity_${convertFromStixType(n.type)}`),
      default_value: defaultValue(n),
      markings: resolveMarkings(stixDomainObjects, n.object_marking_refs),
    }));
    const sort = R.sortWith(
      orderAsc ? [R.ascend(R.prop(sortBy))] : [R.descend(R.prop(sortBy))],
    );
    const sortedContainers = sort(resolvedContainers);
    return (
      <div>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem
            classes={{ root: classes.itemHead }}
            divider={false}
            style={{ paddingTop: 0 }}
          >
            <ListItemIcon
              style={{
                minWidth: 38,
              }}
              onClick={handleToggleSelectAll}
            >
              <Checkbox edge="start" checked={selectAll} disableRipple={true} />
            </ListItemIcon>
            <ListItemIcon>
              <span
                style={{
                  padding: '0 8px 0 8px',
                  fontWeight: 700,
                  fontSize: 12,
                }}
              >
                &nbsp;
              </span>
            </ListItemIcon>
            <ListItemText
              primary={
                <div>
                  {sortHeader('ttype', 'Type', true)}
                  {sortHeader('default_value', 'Default value', true)}
                  {sortHeader('labels', 'Labels', true)}
                  {sortHeader('markings', 'Marking definitions', true)}
                  {sortHeader('in_platform', 'Already in plat.', true)}
                </div>
              }
            />
            <ListItemSecondaryAction>&nbsp;</ListItemSecondaryAction>
          </ListItem>
          {sortedContainers.map((object) => {
            const type = convertFromStixType(object.type);
            return (
              <ListItem
                key={object.id}
                classes={{ root: classes.item }}
                divider
                button={object.type !== 'marking-definition'}
                onClick={() => handleOpenContainer(object.type, object.id)}
              >
                <ListItemIcon
                  classes={{ root: classes.itemIcon }}
                  style={{ minWidth: 40 }}
                  onClick={(event) => handleToggleSelectObject(object, event)}
                >
                  <Checkbox
                    edge="start"
                    checked={
                      (selectAll
                        && !(object.id in (deSelectedElements || {})))
                      || object.id in (selectedElements || {})
                    }
                    disableRipple={true}
                  />
                </ListItemIcon>
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <ItemIcon type={type} />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.ttype}
                      >
                        {object.ttype}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.default_value}
                      >
                        {object.default_value || t('Unknown')}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.labels}
                      >
                        <StixItemLabels
                          variant="inList"
                          labels={object.labels || []}
                        />
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.markings}
                      >
                        <StixItemMarkings
                          variant="inList"
                          markingDefinitions={object.markings || []}
                          limit={2}
                        />
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.in_platform}
                      >
                        {object.default_value
                        && object.type !== 'marking-definition' ? (
                          <QueryRenderer
                            query={stixDomainObjectsLinesSearchQuery}
                            variables={{
                              types: [type],
                              filters: [
                                {
                                  key: [
                                    'name',
                                    'aliases',
                                    'x_opencti_aliases',
                                    'x_mitre_id',
                                  ],
                                  values:
                                    object.name
                                    || object.value
                                    || object.definition
                                    || 'Unknown',
                                },
                              ],
                              count: 1,
                            }}
                            render={({ props }) => {
                              if (props && props.stixDomainObjects) {
                                return props.stixDomainObjects.edges.length
                                  > 0 ? (
                                  <ItemBoolean
                                    variant="inList"
                                    status={true}
                                    label={t('Yes')}
                                  />
                                  ) : (
                                  <ItemBoolean
                                    variant="inList"
                                    status={false}
                                    label={t('No')}
                                  />
                                  );
                              }
                              return (
                                <ItemBoolean
                                  variant="inList"
                                  status={undefined}
                                  label={t('Pending')}
                                />
                              );
                            }}
                          />
                          ) : (
                          <ItemBoolean
                            variant="inList"
                            status={null}
                            label={t('Not applicable')}
                          />
                          )}
                      </div>
                    </div>
                  }
                />
                <ListItemSecondaryAction>
                  <IconButton
                    onClick={() => handleDeleteObject(object)}
                    aria-haspopup="true"
                  >
                    <DeleteOutlined />
                  </IconButton>
                </ListItemSecondaryAction>
              </ListItem>
            );
          })}
        </List>
        <Fab
          onClick={() => handleOpenContainer(null, null)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Drawer
          open={containerStep != null}
          anchor="right"
          sx={{ zIndex: 1202 }}
          elevation={1}
          classes={{ paper: classes.drawerPaper }}
          onClose={handleCloseContainer}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={handleCloseContainer}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t('Manage a container')}</Typography>
          </div>
          <div className={classes.container}>
            {!containerType && renderContainerTypesList()}
            {containerType && containerStep === 0 && renderContainerForm()}
            {containerType && containerStep === 1 && renderContainerContext()}
          </div>
        </Drawer>
      </div>
    );
  };
  // endregion

  return (
    <div className={classes.container}>
      <Typography
        variant="h1"
        gutterBottom={true}
        classes={{ root: classes.title }}
      >
        {file.name.replace('.json', '')}
      </Typography>
      <div className={classes.popover}>
        <WorkbenchFilePopover file={file} />
      </div>
      <div style={{ float: 'right' }}>
        <Button
          variant="contained"
          onClick={handleOpenValidate}
          startIcon={<CheckCircleOutlined />}
          size="small"
        >
          {t('Validate this workbench')}
        </Button>
      </div>
      <div className="clearfix" />
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={currentTab} onChange={handleChangeTab}>
          <Tab label={`${t('Entities')} (${stixDomainObjects.length})`} />
          <Tab label={`${t('Observables')} (${stixCyberObservables.length})`} />
          <Tab
            label={`${t('Relationships')} (${stixCoreRelationships.length})`}
          />
          <Tab label={`${t('Containers')} (${containers.length})`} />
        </Tabs>
      </Box>
      {currentTab === 0 && renderEntities()}
      {currentTab === 1 && renderObservables()}
      {currentTab === 2 && renderRelationships()}
      {currentTab === 3 && renderContainers()}
      <Dialog
        open={!!deleteObject}
        PaperProps={{ elevation: 1 }}
        keepMounted
        TransitionComponent={Transition}
        onClose={handleCloseDeleteObject}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to remove this object?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDeleteObject}>{t('Cancel')}</Button>
          <Button color="secondary" onClick={() => submitDeleteObject()}>
            {t('Remove')}
          </Button>
        </DialogActions>
      </Dialog>
      <Formik
        enableReinitialize={true}
        initialValues={{
          connector_id: connectors.length > 0 ? connectors[0].id : '',
        }}
        validationSchema={importValidation(t)}
        onSubmit={onSubmitValidate}
        onReset={handleCloseValidate}
      >
        {({ submitForm, handleReset, isSubmitting }) => (
          <Form style={{ margin: '0 0 20px 0' }}>
            <Dialog
              open={displayValidate}
              PaperProps={{ elevation: 1 }}
              keepMounted
              onClose={handleCloseValidate}
              fullWidth
            >
              <DialogTitle>{t('Validate and send for import')}</DialogTitle>
              <DialogContent>
                <Field
                  component={SelectField}
                  variant="standard"
                  name="connector_id"
                  label={t('Connector')}
                  fullWidth
                  containerstyle={{ width: '100%' }}
                >
                  {connectors.map((connector) => (
                    <MenuItem
                      key={connector.id}
                      value={connector.id}
                      disabled={!connector.active}
                    >
                      {connector.name}
                    </MenuItem>
                  ))}
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
      <WorkbenchFileToolbar
        selectAll={selectAll}
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        numberOfSelectedElements={numberOfSelectedElements}
        handleClearSelectedElements={handleClearSelectedElements}
        submitDelete={handleDeleteObjects}
        submitApplyMarking={onSubmitApplyMarking}
      />
    </div>
  );
};

const WorkbenchFileContent = createFragmentContainer(
  WorkbenchFileContentComponent,
  {
    connectorsImport: graphql`
      fragment WorkbenchFileContent_connectorsImport on Connector
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
      fragment WorkbenchFileContent_file on File {
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
            ... on Grouping {
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
            ... on AdministrativeArea {
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
            ... on Event {
              name
            }
            ... on Channel {
              name
            }
            ... on Narrative {
              name
            }
            ... on Language {
              name
            }
            ... on DataComponent {
              name
            }
            ... on DataSource {
              name
            }
            ... on Case {
              name
            }
            ... on Feedback {
              name
            }
            ... on Task {
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

export default WorkbenchFileContent;
