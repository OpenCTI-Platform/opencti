import { Add, ArrowDropDown, ArrowDropUp, DeleteOutlined, DoubleArrow } from '@mui/icons-material';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import Checkbox from '@mui/material/Checkbox';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Fab from '@mui/material/Fab';
import IconButton from '@common/button/IconButton';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import MenuItem from '@mui/material/MenuItem';
import Select from '@mui/material/Select';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import Axios from 'axios';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import React, { useEffect, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { v4 as uuid } from 'uuid';
import * as Yup from 'yup';
import Alert from '@mui/material/Alert';
import { ListItemButton } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import DateTimePickerField from '../../../../../components/DateTimePickerField';
import { useFormatter } from '../../../../../components/i18n';
import ItemBoolean from '../../../../../components/ItemBoolean';
import ItemIcon from '../../../../../components/ItemIcon';
import MarkdownField from '../../../../../components/fields/MarkdownField';
import SelectField from '../../../../../components/fields/SelectField';
import StixItemLabels from '../../../../../components/StixItemLabels';
import StixItemMarkings from '../../../../../components/StixItemMarkings';
import SwitchField from '../../../../../components/fields/SwitchField';
import TextField from '../../../../../components/TextField';
import { APP_BASE_PATH, commitMutation, handleError, MESSAGING$, QueryRenderer } from '../../../../../relay/environment';
import { observableValue, resolveIdentityClass, resolveIdentityType, resolveLink, resolveLocationType, resolveThreatActorType } from '../../../../../utils/Entity';
import { defaultKey, getMainRepresentative } from '../../../../../utils/defaultRepresentatives';
import useAttributes from '../../../../../utils/hooks/useAttributes';
import useVocabularyCategory from '../../../../../utils/hooks/useVocabularyCategory';
import { computeDuplicates, convertFromStixType, convertToStixType, truncate, uniqWithByFields } from '../../../../../utils/String';
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
import RichTextField from '../../../../../components/fields/RichTextField';
import Drawer from '../../drawer/Drawer';
import { markingDefinitionsLinesSearchQuery } from '../../../settings/MarkingDefinitionsQuery';
import { KNOWLEDGE_KNUPDATE } from '../../../../../utils/hooks/useGranted';
import Security from '../../../../../utils/Security';
import DeleteDialog from '../../../../../components/DeleteDialog';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import Breadcrumbs from '../../../../../components/Breadcrumbs';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
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
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  default_value: {
    float: 'left',
    width: '30%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  labels: {
    float: 'left',
    width: '22%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
    cursor: 'default',
  },
  markings: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  in_platform: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
    cursor: 'default',
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
    paddingRight: 10,
  },
  default_value: {
    float: 'left',
    width: '30%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  labels: {
    float: 'left',
    width: '22%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  markings: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  in_platform: {
    float: 'left',
    width: '8%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
};

export const workbenchFileContentAttributesQuery = graphql`
  query WorkbenchFileContentAttributesQuery($elementType: [String]!) {
    schemaAttributeNames(elementType: $elementType) {
      edges {
        node {
          value
        }
      }
    }
  }
`;

const workbenchFileContentMutation = graphql`
  mutation WorkbenchFileContentMutation($file: Upload!, $entityId: String, $file_markings: [String!], $refreshEntity: Boolean) {
    uploadPending(file: $file, entityId: $entityId, file_markings: $file_markings, refreshEntity: $refreshEntity) {
      id
    }
  }
`;

const importValidation = (t) => Yup.object().shape({
  connector_id: Yup.string().trim().required(t('This field is required')),
});

const uniqStixDomainObjectsFields = ['name', 'type', 'pattern', 'identity_class', 'x_opencti_location_type'];

// for an entity, get a default value that can be filtered (to check if the entity is in the platform)
// (simplified version of getMainRepresentative with only the filterable attributes)
const getEntityMainRepresentativeForWorkbenchChecks = (n, fallback = 'Unknown') => {
  if (!n) return '';
  const mainValue = n.name
    || n.pattern
    || n.attribute_abstract
    || n.opinion
    || n.value
    || n.source_name
    || n.phase_name
    || n.result_name
    || n.content
    || n.key
    || n.path
    || (n.hashes
      && (n.hashes.MD5
        || n.hashes['SHA-1']
        || n.hashes['SHA-256']
        || n.hashes['SHA-512']))
      || getEntityMainRepresentativeForWorkbenchChecks((R.head(n.objects?.edges ?? []))?.node)
      || n.main_entity_name
      || n.dst_port
      || fallback;
  return mainValue;
};

const defaultValueKeys = {
  stixDomainObjects: [
    'name',
    'aliases',
    'x_opencti_aliases',
    'x_mitre_id',
    'pattern',
    'attribute_abstract',
    'opinion',
    'value',
    'source_name',
    'phase_name',
    'result_name',
    'content',
    'main_entity_name',
  ],
  stixCyberObservables: [
    'name',
    'value',
    'aliases',
    'x_opencti_aliases',
    'value',
    'content',
    'attribute_key',
    'path',
    'hashes.MD5',
    'hashes.SHA-1',
    'hashes.SHA-256',
    'hashes.SHA-512',
  ],
};

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
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const classes = useStyles();

  // region state
  const [currentTab, setCurrentTab] = useState(0);

  const [stixDomainObjects, setStixDomainObjects] = useState([]);
  const [stixCyberObservables, setStixCyberObservables] = useState([]);
  const [stixCoreRelationships, setStixCoreRelationships] = useState([]);
  const [stixSightings, setStixSightings] = useState([]);
  const [containers, setContainers] = useState([]);

  const [fileObjectsJson, setFileObjectsJson] = useState('');

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
  const [displayConvertToDraft, setDisplayConvertToDraft] = useState(false);

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
    const newStixSightings = objects.filter(
      (n) => n.type === 'sighting' && n.id,
    );
    setStixDomainObjects(newStixDomainObjects);
    setStixCyberObservables(newStixCyberObservables);
    setStixCoreRelationships(newStixCoreRelationships);
    setStixSightings(newStixSightings);
    setContainers(newContainers);
  };
  // endregion

  // region file
  const loadFileContent = () => {
    const url = `${APP_BASE_PATH}/storage/view/${encodeURIComponent(file.id)}`;
    Axios.get(url).then(async (res) => {
      const fileObjects = res.data.objects ?? [];
      setFileObjectsJson(JSON.stringify(fileObjects));
      computeState(fileObjects);
      return true;
    });
  };

  const saveFile = () => {
    const numberOfObjects = stixDomainObjects.length
      + stixCyberObservables.length
      + stixCoreRelationships.length
      + stixSightings.length
      + containers.length;
    if (numberOfObjects > 0) {
      const currentEntityId = file.metaData.entity_id && file.metaData.entity ? file.metaData.entity_id : null;
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
      const objects = [
        ...stixDomainObjects,
        ...stixCyberObservables,
        ...stixCoreRelationships,
        ...stixSightings,
        ...containers,
      ];
      const objectsJson = JSON.stringify(objects);
      if (objectsJson !== fileObjectsJson) { // check that objects have changed
        setFileObjectsJson(objectsJson);
        const data = {
          id: `bundle--${uuid()}`,
          type: 'bundle',
          objects,
        };
        const json = JSON.stringify(data);
        const blob = new Blob([json], { type: 'text/json' });
        const fileToUpload = new File([blob], file.name, {
          type: 'application/json',
        });
        commitMutation({
          mutation: workbenchFileContentMutation,
          variables: {
            file: fileToUpload,
            entityId: currentEntityId,
            file_markings: file.metaData.file_markings ?? [],
          },
        });
      }
    }
  };

  useEffect(() => loadFileContent(), []);
  useEffect(
    () => saveFile(),
    [
      JSON.stringify(stixDomainObjects),
      JSON.stringify(stixCyberObservables),
      JSON.stringify(stixCoreRelationships),
      JSON.stringify(stixSightings),
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
    elements = stixSightings;
  } else if (currentTab === 4) {
    elements = containers;
  }
  if (selectAll) {
    numberOfSelectedElements = elements.length - Object.keys(deSelectedElements || {}).length;
  }

  const deletion = useDeletion({});
  const { handleOpenDelete, handleCloseDelete } = deletion;
  // endregion

  // region control
  const handleOpenValidate = () => setDisplayValidate(true);
  const handleCloseValidate = () => setDisplayValidate(false);

  const handleOpenConvertToDraft = () => setDisplayConvertToDraft(true);
  const handleCloseConvertToDraft = () => setDisplayConvertToDraft(false);

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
  const handleDeleteObject = (object) => {
    setDeleteObject(object);
    handleOpenDelete();
  };

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
      objects = stixSightings;
    } else if (currentTab === 4) {
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
    let finalStixSightings = stixSightings.filter(
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
    finalStixSightings = finalStixSightings.map((n) => (objectsToBeDeletedIds.includes(n.created_by_ref)
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
    finalStixSightings = finalStixSightings.map((n) => R.assoc(
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
    const stixSightingsToRemove = finalStixSightings
      .filter(
        (n) => objectsToBeDeletedIds.includes(n.sighting_of_ref)
          || objectsToBeDeletedIds.includes(n.where_sighted_refs?.at(0)),
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
    finalStixSightings = finalStixSightings.filter(
      (n) => !stixSightingsToRemove.includes(n.id),
    );
    setStixDomainObjects(finalStixDomainObjects);
    setStixCyberObservables(finalStixCyberObservables);
    setStixCoreRelationships(finalStixCoreRelationships);
    setStixSightings(finalStixSightings);
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
    const currentEntityId = file.metaData.entity_id && file.metaData.entity ? file.metaData.entity_id : null;
    const data = {
      id: `bundle--${uuid()}`,
      type: 'bundle',
      objects: [
        ...stixDomainObjects,
        ...stixCyberObservables,
        ...stixCoreRelationships,
        ...stixSightings,
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
      variables: {
        file: fileToUpload,
        entityId: currentEntityId,
        file_markings: file.metaData.file_markings ?? [],
        refreshEntity: values.refreshEntity,
      },
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
                navigate(`${entityLink}/files`);
              } else {
                navigate('/dashboard/data/import');
              }
            },
            onError: (error) => {
              handleError(error);
              setSubmitting(false);
              resetForm();
              setDisplayValidate(false);
            },
          });
        }, 2000);
      },
    });
  };

  const onSubmitConvertToDraft = (values, { setSubmitting, resetForm }) => {
    const currentEntityId = file.metaData.entity_id && file.metaData.entity ? file.metaData.entity_id : null;
    const data = {
      id: `bundle--${uuid()}`,
      type: 'bundle',
      objects: [
        ...stixDomainObjects,
        ...stixCyberObservables,
        ...stixCoreRelationships,
        ...stixSightings,
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
      variables: {
        file: fileToUpload,
        entityId: currentEntityId,
        file_markings: file.metaData.file_markings ?? [],
        refreshEntity: values.refreshEntity,
      },
      onCompleted: () => {
        setTimeout(() => {
          commitMutation({
            mutation: fileManagerAskJobImportMutation,
            variables: {
              fileName: file.id,
              connectorId: values.connector_id,
              bypassValidation: false,
              forceValidation: true, // force validation to create draft
              validationMode: 'draft',
            },
            onCompleted: () => {
              setSubmitting(false);
              resetForm();
              setDisplayValidate(false);
              MESSAGING$.notifySuccess('Convertion to draft successfully asked');
              if (file.metaData.entity) {
                const entityLink = `${resolveLink(
                  file.metaData.entity.entity_type,
                )}/${file.metaData.entity.id}`;
                navigate(`${entityLink}/files`);
              } else {
                navigate('/dashboard/data/import/draft');
              }
            },
            onError: (error) => {
              handleError(error);
              setSubmitting(false);
              resetForm();
              setDisplayValidate(false);
            },
          });
        }, 2000);
      },
    });
  };

  const onSubmitApplyMarking = (values, { resetForm }) => {
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
      objects = stixSightings;
    } else if (currentTab === 4) {
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
    const objectsToBeProccessedIds = objectsToBeProcessed.map((n) => n.id);
    const filteredObjects = objects.filter((n) => !objectsToBeProccessedIds.includes(n.id));
    const objectsToAdd = objectsToBeProcessed.map((n) => ({
      ...n,
      object_marking_refs: R.uniq([
        ...(n.object_marking_refs || []),
        ...markingDefinitions.map((o) => o.id),
      ]),
    }));
    const finalObjects = filteredObjects.concat(objectsToAdd);
    if (currentTab === 0) {
      setStixDomainObjects(
        R.uniqBy(R.prop('id'), [
          ...finalObjects,
          ...markingDefinitions,
        ]),
      );
    } else {
      setStixDomainObjects(
        R.uniqBy(R.prop('id'), [
          ...stixDomainObjects,
          ...markingDefinitions,
        ]),
      );
    }
    if (currentTab === 1) {
      setStixCyberObservables(finalObjects);
    } else if (currentTab === 2) {
      setStixCoreRelationships(finalObjects);
    } else if (currentTab === 3) {
      setStixSightings(finalObjects);
    } else if (currentTab === 4) {
      setContainers(finalObjects);
    }
    resetForm();
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
    let finalStixSightings = stixSightings.filter(
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
      finalStixSightings = finalStixSightings.map((n) => (n.created_by_ref === toDeleteObject.id
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
      finalStixSightings = finalStixSightings.map((n) => R.assoc(
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
    const stixSightingsToRemove = finalStixSightings
      .filter(
        (n) => n.sighting_of_ref === toDeleteObject.id
          || n.where_sighted_refs?.at(0) === toDeleteObject.id,
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
    finalStixSightings = finalStixSightings.filter(
      (n) => !stixSightingsToRemove.includes(n.id),
    );
    setStixDomainObjects(finalStixDomainObjects);
    setStixCyberObservables(finalStixCyberObservables);
    setStixCoreRelationships(finalStixCoreRelationships);
    setStixSightings(finalStixSightings);
    setContainers(finalContainers);
    setDeleteObject(null);
    handleCloseDelete();
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
    const stixValues = R.reject(R.anyPass([R.isEmpty, R.isNil]))({
      ...entity,
      ...finalValues,
    });
    const stixType = convertToStixType(entityType);
    const updatedEntity = {
      ...stixValues,
      id: entity.id ? entity.id : `${stixType}--${uuid()}`,
      type: stixType,
    };
    if (updatedEntity.type === 'identity' && !updatedEntity.identity_class) {
      updatedEntity.identity_class = resolveIdentityClass(entityType);
    } else if (updatedEntity.type === 'location' && !updatedEntity.x_opencti_location_type) {
      updatedEntity.x_opencti_location_type = entityType;
    }
    if (updatedEntity.type === 'threat-actor' && !updatedEntity.x_opencti_type) {
      updatedEntity.x_opencti_type = entityType;
    }
    setStixDomainObjects(
      uniqWithByFields(
        uniqStixDomainObjectsFields,
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
        uniqStixDomainObjectsFields,
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
    const stixValues = R.reject(R.anyPass([R.isEmpty, R.isNil]))({
      ...relationship,
      ...finalValues,
    });
    const updatedRelationship = {
      ...stixValues,
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
        uniqStixDomainObjectsFields,
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
    if (values['hashes.MD5'] && values['hashes.MD5'].length > 0) {
      hashes.MD5 = values['hashes.MD5'];
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
          'hashes.MD5',
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
    const stixValues = R.reject(R.anyPass([R.isEmpty, R.isNil]))({
      ...observable,
      ...finalValues,
    });
    const stixType = convertToStixType(observableType);
    const updatedObservable = {
      ...stixValues,
      id: observable.id ? observable.id : `${stixType}--${uuid()}`,
      type: stixType,
      observable_value: observableValue({
        ...observable,
        ...finalValues,
        entity_type: observableType,
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
        uniqStixDomainObjectsFields,
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
      ...R.indexBy(R.prop('id'), stixSightings),
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
    const stixValues = R.reject(R.anyPass([R.isEmpty, R.isNil]))({
      ...container,
      ...finalValues,
    });
    const stixType = convertToStixType(containerType);
    const updatedContainer = {
      ...stixValues,
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
        uniqStixDomainObjectsFields,
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
      ...R.indexBy(R.prop('id'), stixSightings),
    };
    let containerElementsIds = [];
    if (containerSelectAll) {
      containerElementsIds = R.uniq(
        R.values(indexedStixObjects)
          .filter(
            (n) => !Object.keys(containerDeselectedElements || {}).includes(n.id)
              && n.type !== 'marking-definition',
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
          <span>{t_i18n(label)}</span>
          {sortBy === field ? sortComponent : ''}
        </div>
      );
    }
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t_i18n(label)}</span>
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
          <span>{t_i18n(label)}</span>
          {containerSortBy === field ? sortComponent : ''}
        </div>
      );
    }
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t_i18n(label)}</span>
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
      R.map((n) => R.assoc('tlabel', t_i18n(`entity_${n.label}`), n)),
      sortByLabel,
    )(subTypesEdges);
    return (
      <List>
        {translatedOrderedList.map((subType) => (
          <ListItemButton
            key={subType.label}
            divider
            dense
            onClick={() => setEntityType(subType.label)}
          >
            <ListItemText primary={subType.tlabel} />
          </ListItemButton>
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
          if (props && props.schemaAttributeNames) {
            const initialValues = {
              createdBy: convertCreatedByRef(entity),
              objectMarking: convertMarkings(entity),
              objectLabel: convertLabels(entity),
              externalReferences: convertExternalReferences(entity),
            };
            const attributes = R.filter(
              (n) => R.includes(
                n,
                R.map((o) => o.node.value, props.schemaAttributeNames.edges),
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
                              textFieldProps={{
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
                        if (
                          R.includes(attribute, vocabularyAttributes)
                          && fieldToCategory(type, attribute)
                        ) {
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
                      setFieldValue={setFieldValue}
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
                        onClick={handleReset}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t_i18n('Cancel')}
                      </Button>
                      <Button
                        startIcon={<DoubleArrow />}
                        // color="secondary"
                        onClick={submitForm}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {entityId
                          ? t_i18n('Update and complete')
                          : t_i18n('Add and complete')}
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
      'Threat-Actor',
      'Intrusion-Set',
      'Campaign',
      'Incident',
      'Malware',
      'Tool',
      'Channel',
    ];
    const usesFrom = [
      'Threat-Actor',
      'Intrusion-Set',
      'Campaign',
      'Incident',
      'Malware',
      'Tool',
      'Channel',
    ];
    const attributedToFrom = [
      'Threat-Actor',
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
      'Administrative-Area',
    ];
    const attributedToTo = ['Threat-Actor', 'Intrusion-Set', 'Campaign'];
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
                title={t_i18n('relationship_targets')}
                fullWidth
                types={[
                  'Administrative-Area',
                  'City',
                  'Country',
                  'Event',
                  'Individual',
                  'Organization',
                  'Position',
                  'Region',
                  'Sector',
                  'System',
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
                title={t_i18n('relationship_uses')}
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
                title={t_i18n('relationship_attributed-to')}
                fullWidth
                types={['Threat-Actor', 'Intrusion-Set', 'Campaign']}
                stixDomainObjects={stixDomainObjects}
                style={{ marginTop: 20 }}
              />
            )}
            {targetsTo.includes(type) && (
              <Field
                component={DynamicResolutionField}
                variant="standard"
                name="targets_to"
                title={t_i18n('relationship_targets')}
                fullWidth
                types={[
                  'Threat-Actor',
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
                title={t_i18n('relationship_attributed-to') + t_i18n(' (reversed)')}
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
                title={t_i18n('relationship_uses') + t_i18n(' (reversed)')}
                fullWidth
                types={[
                  'Threat-Actor',
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
                onClick={handleReset}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                color="secondary"
                onClick={() => submitForm(false)}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t_i18n('Add context')}
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
          if (props && props.schemaAttributeNames) {
            const initialValues = {
              createdBy: convertCreatedByRef(relationship),
              objectMarking: convertMarkings(relationship),
              objectLabel: convertLabels(relationship),
              externalReferences: convertExternalReferences(relationship),
            };
            const attributes = R.filter(
              (n) => R.includes(
                n,
                R.map((o) => o.node.value, props.schemaAttributeNames.edges),
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
                              textFieldProps={{
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
                      setFieldValue={setFieldValue}
                    />
                    <ExternalReferencesField
                      name="externalReferences"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      values={values.externalReferences}
                    />
                    <div className={classes.buttons}>
                      <Button
                        onClick={handleReset}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t_i18n('Cancel')}
                      </Button>
                      <Button
                        // color="secondary"
                        onClick={submitForm}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t_i18n('Update')}
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
      R.map((n) => R.assoc('tlabel', t_i18n(`entity_${n.label}`), n)),
      sortByLabel,
    )(subTypesEdges);
    return (
      <List>
        {translatedOrderedList.map((subType) => (
          <ListItemButton
            key={subType.label}
            divider
            dense
            onClick={() => setObservableType(subType.label)}
          >
            <ListItemText primary={subType.tlabel} />
          </ListItemButton>
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
          if (props && props.schemaAttributeNames) {
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
            )(props.schemaAttributeNames.edges);
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
                initialValues['hashes.MD5'] = observable[attribute]
                  ? observable[attribute].MD5 ?? ''
                  : '';
                initialValues['hashes_SHA-1'] = observable[attribute]
                  ? observable[attribute]['SHA-1'] ?? ''
                  : '';
                initialValues['hashes_SHA-256'] = observable[attribute]
                  ? observable[attribute]['SHA-256'] ?? ''
                  : '';
                initialValues['hashes_SHA-512'] = observable[attribute]
                  ? observable[attribute]['SHA-512'] ?? ''
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
                              textFieldProps={{
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
                                name="hashes.MD5"
                                label={t_i18n('hash_md5')}
                                fullWidth
                                style={{ marginTop: 20 }}
                              />
                              <Field
                                component={TextField}
                                variant="standard"
                                name="hashes_SHA-1"
                                label={t_i18n('hash_sha-1')}
                                fullWidth
                                style={{ marginTop: 20 }}
                              />
                              <Field
                                component={TextField}
                                variant="standard"
                                name="hashes_SHA-256"
                                label={t_i18n('hash_sha-256')}
                                fullWidth
                                style={{ marginTop: 20 }}
                              />
                              <Field
                                component={TextField}
                                variant="standard"
                                name="hashes.SHA-512"
                                label={t_i18n('hash_sha-512')}
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
                        if (
                          R.includes(attribute, vocabularyAttributes)
                          && fieldToCategory(observableType, attribute)
                        ) {
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
                      setFieldValue={setFieldValue}
                    />
                    <ExternalReferencesField
                      name="externalReferences"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      values={values.externalReferences}
                    />
                    <div className={classes.buttons}>
                      <Button
                        onClick={handleReset}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t_i18n('Cancel')}
                      </Button>
                      <Button
                        // color="secondary"
                        onClick={submitForm}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {observableId ? t_i18n('Update') : t_i18n('Add')}
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
          if (props && props.schemaAttributeNames) {
            const initialValues = {
              createdBy: convertCreatedByRef(container),
              objectMarking: convertMarkings(container),
              objectLabel: convertLabels(container),
              externalReferences: convertExternalReferences(container),
            };
            const attributes = R.filter(
              (n) => R.includes(
                n,
                R.map((o) => o.node.value, props.schemaAttributeNames.edges),
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
                              textFieldProps={{
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
                        if (
                          R.includes(attribute, markdownAttributes)
                          || (containerType === 'Note' && attribute === 'content')
                        ) {
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
                        if (
                          R.includes(attribute, vocabularyAttributes)
                          && fieldToCategory(containerType, attribute)
                        ) {
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
                      setFieldValue={setFieldValue}
                    />
                    <ExternalReferencesField
                      name="externalReferences"
                      style={fieldSpacingContainerStyle}
                      setFieldValue={setFieldValue}
                      values={values.externalReferences}
                    />
                    <div className={classes.buttons}>
                      <Button
                        variant="secondary"
                        onClick={handleReset}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t_i18n('Cancel')}
                      </Button>
                      <Button
                        startIcon={<DoubleArrow />}
                        onClick={submitForm}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {containerId
                          ? t_i18n('Update and complete')
                          : t_i18n('Add and complete')}
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
      ...R.indexBy(R.prop('id'), stixSightings),
    };
    const resolvedObjects = R.values(indexedStixObjects).map((n) => ({
      ...n,
      ttype:
        n.type === 'relationship'
          ? t_i18n(`relationship_${n.relationship_type}`)
          : t_i18n(`entity_${convertFromStixType(n.type)}`),
      default_value: getMainRepresentative({
        ...n,
        source_ref_name: getMainRepresentative(
          indexedStixObjects[n.source_ref]
          || indexedStixObjects[n.sighting_of_ref]
          || {},
        ),
        target_ref_name: getMainRepresentative(
          indexedStixObjects[n.target_ref]
          || indexedStixObjects[n.where_sighted_refs?.at(0)]
          || {},
        ),
      }, null),
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
          <ListItemButton
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
              primary={(
                <div>
                  {sortHeaderContainer('ttype', 'Type', true)}
                  {sortHeaderContainer('default_value', 'Default value', true)}
                  {sortHeaderContainer('labels', 'Labels', true)}
                  {sortHeaderContainer('markings', 'Marking definitions', true)}
                </div>
              )}
            />
          </ListItemButton>
          {sortedObjects.map((object) => {
            let type = convertFromStixType(object.type);
            let secondaryType = '';
            if (type === 'Identity') {
              type = resolveIdentityType(object.identity_class);
              secondaryType = ` (${t_i18n(
                `entity_${resolveIdentityType(object.identity_class)}`,
              )})`;
            }
            if (type === 'Location') {
              type = resolveLocationType(object);
              secondaryType = ` (${t_i18n(
                `entity_${resolveLocationType(object)}`,
              )})`;
            }
            if (type === 'Threat-Actor') {
              type = resolveThreatActorType(object);
              secondaryType = ` (${t_i18n(
                `entity_${resolveThreatActorType(object)}`,
              )})`;
            }
            return (
              <ListItem
                key={object.id}
                classes={{ root: classes.item }}
                divider
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
                  primary={(
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
                  )}
                />
              </ListItem>
            );
          })}
        </List>
        <div className={classes.buttons}>
          <Button
            variant="secondary"
            onClick={handleCloseContainer}
            classes={{ root: classes.button }}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={onSubmitContainerContext}
            classes={{ root: classes.button }}
          >
            {t_i18n('Update context')}
          </Button>
        </div>
      </div>
    );
  };

  const renderEntities = () => {
    const resolvedStixDomainObjects = stixDomainObjects.map((n) => ({
      ...n,
      ttype: t_i18n(`entity_${convertFromStixType(n.type)}`),
      default_value: getEntityMainRepresentativeForWorkbenchChecks(n, null),
      // use an adapted version of getMainRepresentative because not possible to filter by representative.main (to check if the entity is in the platform)
      markings: resolveMarkings(stixDomainObjects, n.object_marking_refs),
    }));
    const sort = R.sortWith(
      orderAsc ? [R.ascend(R.prop(sortBy))] : [R.descend(R.prop(sortBy))],
    );
    const sortedStixDomainObjects = sort(resolvedStixDomainObjects);

    const objectExistenceItem = (object, type) => {
      if (type === 'Marking-Definition') {
        return (
          <QueryRenderer
            query={markingDefinitionsLinesSearchQuery}
            variables={{
              filters: {
                mode: 'and',
                filters: [{ key: 'definition', values: [object.name] }],
                filterGroups: [],
              },
              first: 1,
            }}
            render={({ props }) => {
              if (props && props.markingDefinitions) {
                return props.markingDefinitions.edges.length > 0
                  ? (
                      <ItemBoolean
                        variant="inList"
                        status={true}
                        label={t_i18n('Yes')}
                      />
                    ) : (
                      <ItemBoolean
                        variant="inList"
                        status={false}
                        label={t_i18n('No')}
                      />
                    );
              }
              return (
                <ItemBoolean
                  variant="inList"
                  status={undefined}
                  label={t_i18n('Pending')}
                />
              );
            }}
          />
        );
      }
      return (
        <QueryRenderer
          query={stixDomainObjectsLinesSearchQuery}
          variables={{
            types: [type],
            filters: {
              mode: 'and',
              filters: [
                {
                  key: defaultValueKeys.stixDomainObjects,
                  values: [object.default_value],
                },
              ],
              filterGroups: [],
            },
            count: 1,
          }}
          render={({ props }) => {
            if (props && props.stixDomainObjects) {
              return props.stixDomainObjects.edges.length > 0
                ? (
                    <ItemBoolean
                      variant="inList"
                      status={true}
                      label={t_i18n('Yes')}
                    />
                  ) : (
                    <ItemBoolean
                      variant="inList"
                      status={false}
                      label={t_i18n('No')}
                    />
                  );
            }
            return (
              <ItemBoolean
                variant="inList"
                status={undefined}
                label={t_i18n('Pending')}
              />
            );
          }}
        />
      );
    };

    return (
      <div>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem
            classes={{ root: classes.itemHead }}
            divider={false}
            disablePadding
            style={{ paddingTop: 0 }}
            secondaryAction={<>&nbsp;</>}
          >
            <ListItemButton
              classes={{ root: classes.itemHead }}
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
                primary={(
                  <div>
                    {sortHeader('ttype', 'Type', true)}
                    {sortHeader('default_value', 'Default value', true)}
                    {sortHeader('labels', 'Labels', false)}
                    {sortHeader('markings', 'Marking definitions', true)}
                    {sortHeader('in_platform', 'Already in plat.', false)}
                  </div>
                )}
              />
            </ListItemButton>
          </ListItem>
          {sortedStixDomainObjects.map((object) => {
            let type = convertFromStixType(object.type);
            let secondaryType = '';
            if (type === 'Identity') {
              type = resolveIdentityType(object.identity_class);
              secondaryType = ` (${t_i18n(
                `entity_${resolveIdentityType(object.identity_class)}`,
              )})`;
            }
            if (type === 'Location') {
              type = resolveLocationType(object);
              secondaryType = ` (${t_i18n(
                `entity_${resolveLocationType(object)}`,
              )})`;
            }
            if (type === 'Threat-Actor') {
              type = resolveThreatActorType(object);
              secondaryType = ` (${t_i18n(
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
                secondaryAction={(
                  <IconButton
                    onClick={() => handleDeleteObject(object)}
                    aria-haspopup="true"
                  >
                    <DeleteOutlined />
                  </IconButton>
                )}
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
                  primary={(
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
                        {object.default_value || t_i18n('Unknown')}
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
                        {object.default_value ? (
                          objectExistenceItem(object, type)
                        ) : (
                          <ItemBoolean
                            variant="inList"
                            status={null}
                            label={t_i18n('Not applicable')}
                          />
                        )}
                      </div>
                    </div>
                  )}
                />
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
          onClose={handleCloseEntity}
          title={t_i18n('Manage an entity')}
        >
          <>
            {!entityType && renderEntityTypesList()}
            {entityType && entityStep === 0 && renderEntityForm()}
            {entityType && entityStep === 1 && renderEntityContext()}
          </>
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
      R.map((n) => R.assoc('tlabel', t_i18n(`entity_${n.label}`), n)),
      sortByLabel,
    )(subTypesEdges);
    const resolvedStixCyberObservables = stixCyberObservables.map((n) => ({
      ...n,
      ttype: t_i18n(`entity_${convertFromStixType(n.type)}`),
      default_value: getEntityMainRepresentativeForWorkbenchChecks(n, null),
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
            secondaryAction={<>&nbsp;</>}
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
              primary={(
                <div>
                  {sortHeader('ttype', 'Type', true)}
                  {sortHeader('default_value', 'Default value', true)}
                  {sortHeader('labels', 'Labels', false)}
                  {sortHeader('markings', 'Marking definitions', true)}
                  {sortHeader('in_platform', 'Already in plat.', false)}
                </div>
              )}
            />
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
                secondaryAction={(
                  <IconButton
                    onClick={() => handleDeleteObject(object)}
                    aria-haspopup="true"
                  >
                    <DeleteOutlined />
                  </IconButton>
                )}
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
                  primary={(
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
                        {object.default_value || t_i18n('Unknown')}
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
                        {object.default_value ? (
                          <QueryRenderer
                            query={stixCyberObservablesLinesSearchQuery}
                            variables={{
                              types: [type],
                              filters: {
                                mode: 'and',
                                filters: [
                                  {
                                    key: defaultValueKeys.stixCyberObservables,
                                    values: [object.default_value],
                                  },
                                ],
                                filterGroups: [],
                              },
                              count: 1,
                            }}
                            render={({ props }) => {
                              if (props && props.stixCyberObservables) {
                                return props.stixCyberObservables.edges.length
                                  > 0 ? (
                                      <ItemBoolean
                                        variant="inList"
                                        status={true}
                                        label={t_i18n('Yes')}
                                      />
                                    ) : (
                                      <ItemBoolean
                                        variant="inList"
                                        status={false}
                                        label={t_i18n('No')}
                                      />
                                    );
                              }
                              return (
                                <ItemBoolean
                                  variant="inList"
                                  status={undefined}
                                  label={t_i18n('Pending')}
                                />
                              );
                            }}
                          />
                        ) : (
                          <ItemBoolean
                            variant="inList"
                            status={null}
                            label={t_i18n('Not applicable')}
                          />
                        )}
                      </div>
                    </div>
                  )}
                />
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
          onClose={handleCloseObservable}
          title={t_i18n('Manage an observable')}
        >
          <>
            {!observableType && renderObservableTypesList()}
            {observableType && renderObservableForm()}
          </>
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
      ttype: t_i18n(`relationship_${n.relationship_type}`),
      default_value: getMainRepresentative({
        ...n,
        source_ref_name: getMainRepresentative(indexedStixObjects[n.source_ref] || {}),
        target_ref_name: getMainRepresentative(indexedStixObjects[n.target_ref] || {}),
      }, null),
      source_ref_name: getMainRepresentative(indexedStixObjects[n.source_ref] || {}),
      target_ref_name: getMainRepresentative(indexedStixObjects[n.target_ref] || {}),
      markings: resolveMarkings(stixDomainObjects, n.object_marking_refs),
    }));
    const sort = R.sortWith(
      orderAsc ? [R.ascend(R.prop(sortBy))] : [R.descend(R.prop(sortBy))],
    );
    const sortedStixCoreRelationships = sort(resolvedStixCoreRelationships);
    return (
      <>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem
            classes={{ root: classes.itemHead }}
            divider={false}
            style={{ paddingTop: 0 }}
            secondaryAction={<>&nbsp;</>}
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
              primary={(
                <div>
                  {sortHeader('ttype', 'Type', true)}
                  {sortHeader('default_value', 'Default value', true)}
                  {sortHeader('labels', 'Labels', false)}
                  {sortHeader('markings', 'Marking definitions', true)}
                </div>
              )}
            />
          </ListItem>
          {sortedStixCoreRelationships.map((object) => (
            <ListItem
              key={object.id}
              divider
              disablePadding
              secondaryAction={(
                <IconButton
                  onClick={() => handleDeleteObject(object)}
                  aria-haspopup="true"
                >
                  <DeleteOutlined />
                </IconButton>
              )}
            >
              <ListItemButton
                classes={{ root: classes.item }}
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
                  primary={(
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
                        {object.default_value || t_i18n('Unknown')}
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
                  )}
                />
              </ListItemButton>
            </ListItem>
          ))}
        </List>
        <Drawer
          open={entityStep != null}
          onClose={handleCloseRelationship}
          title={t_i18n('Manage a relationship')}
        >
          <>{relationshipId && renderRelationshipForm()}</>
        </Drawer>
      </>
    );
  };

  const renderSightings = () => {
    const indexedStixObjects = {
      ...R.indexBy(R.prop('id'), stixDomainObjects),
      ...R.indexBy(R.prop('id'), stixCyberObservables),
    };
    const resolvedStixSightings = stixSightings.map((n) => ({
      ...n,
      ttype: t_i18n('Sighting'),
      default_value: getMainRepresentative({
        ...n,
        source_ref_name: getMainRepresentative(
          indexedStixObjects[n.sighting_of_ref] || {},
        ),
        target_ref_name: getMainRepresentative(
          indexedStixObjects[n.where_sighted_refs?.at(0)] || {},
        ),
      }, null),
      source_ref_name: getMainRepresentative(
        indexedStixObjects[n.sighting_of_ref] || {},
      ),
      target_ref_name: getMainRepresentative(
        indexedStixObjects[n.where_sighted_refs?.at(0)] || {},
      ),
      markings: resolveMarkings(stixDomainObjects, n.object_marking_refs),
    }));
    const sort = R.sortWith(
      orderAsc ? [R.ascend(R.prop(sortBy))] : [R.descend(R.prop(sortBy))],
    );
    const sortedStixSightings = sort(resolvedStixSightings);
    return (
      <>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem
            classes={{ root: classes.itemHead }}
            divider={false}
            style={{ paddingTop: 0 }}
            secondaryAction={<>&nbsp;</>}
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
              primary={(
                <div>
                  {sortHeader('ttype', 'Type', true)}
                  {sortHeader('default_value', 'Default value', true)}
                  {sortHeader('labels', 'Labels', false)}
                  {sortHeader('markings', 'Marking definitions', true)}
                </div>
              )}
            />
          </ListItem>
          {sortedStixSightings.map((object) => (
            <ListItem
              key={object.id}
              divider
              disablePadding
              secondaryAction={(
                <IconButton
                  onClick={() => handleDeleteObject(object)}
                  aria-haspopup="true"
                >
                  <DeleteOutlined />
                </IconButton>
              )}
            >
              <ListItemButton
                classes={{ root: classes.item }}
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
                  <ItemIcon type="sighting" />
                </ListItemIcon>
                <ListItemText
                  primary={(
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
                        {object.default_value || t_i18n('Unknown')}
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
                  )}
                />
              </ListItemButton>
            </ListItem>
          ))}
        </List>
      </>
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
        'x-opencti-case-rft',
        'case-rft',
        'x-opencti-task',
        'task',
      ].includes(convertToStixType(n.label))),
      R.map((n) => R.assoc('tlabel', t_i18n(`entity_${n.label}`), n)),
      sortByLabel,
    )(subTypesEdges);
    return (
      <List>
        {translatedOrderedList.map((subType) => (
          <ListItemButton
            key={subType.label}
            divider
            dense
            onClick={() => setContainerType(subType.label)}
          >
            <ListItemText primary={subType.tlabel} />
          </ListItemButton>
        ))}
      </List>
    );
  };

  const renderContainers = () => {
    const resolvedContainers = containers.map((n) => ({
      ...n,
      ttype: t_i18n(`entity_${convertFromStixType(n.type)}`),
      default_value: getMainRepresentative(n, null),
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
            secondaryAction={<>&nbsp;</>}
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
              primary={(
                <div>
                  {sortHeader('ttype', 'Type', true)}
                  {sortHeader('default_value', 'Default value', true)}
                  {sortHeader('labels', 'Labels', false)}
                  {sortHeader('markings', 'Marking definitions', true)}
                  {sortHeader('in_platform', 'Already in plat.', false)}
                </div>
              )}
            />

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
                secondaryAction={(
                  <IconButton
                    onClick={() => handleDeleteObject(object)}
                    aria-haspopup="true"
                  >
                    <DeleteOutlined />
                  </IconButton>
                )}
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
                  primary={(
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
                        {object.default_value || t_i18n('Unknown')}
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
                        {object.default_value ? (
                          <QueryRenderer
                            query={stixDomainObjectsLinesSearchQuery}
                            variables={{
                              types: [type],
                              filters: {
                                mode: 'and',
                                filters: [
                                  {
                                    key: defaultValueKeys.stixDomainObjects,
                                    values: [object.default_value],
                                  },
                                  {
                                    key: 'created',
                                    values: [object.created ?? now()],
                                  },
                                ],
                                filterGroups: [],
                              },
                              count: 1,
                            }}
                            render={({ props }) => {
                              if (props && props.stixDomainObjects) {
                                return props.stixDomainObjects.edges.length
                                  > 0 ? (
                                      <ItemBoolean
                                        variant="inList"
                                        status={true}
                                        label={t_i18n('Yes')}
                                      />
                                    ) : (
                                      <ItemBoolean
                                        variant="inList"
                                        status={false}
                                        label={t_i18n('No')}
                                      />
                                    );
                              }
                              return (
                                <ItemBoolean
                                  variant="inList"
                                  status={undefined}
                                  label={t_i18n('Pending')}
                                />
                              );
                            }}
                          />
                        ) : (
                          <ItemBoolean
                            variant="inList"
                            status={null}
                            label={t_i18n('Not applicable')}
                          />
                        )}
                      </div>
                    </div>
                  )}
                />
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
          onClose={handleCloseContainer}
          title={t_i18n('Manage a container')}
        >
          <>
            {!containerType && renderContainerTypesList()}
            {containerType && containerStep === 0 && renderContainerForm()}
            {containerType && containerStep === 1 && renderContainerContext()}
          </>
        </Drawer>
      </div>
    );
  };
  // endregion
  const fileName = file.name.replace('.json', '');
  return (
    <div className={classes.container}>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Data') },
          { label: t_i18n('Import'), link: '/dashboard/data/import' },
          { label: t_i18n('Analyst workbenches'), link: '/dashboard/data/import/workbench' },
          { label: fileName, current: true },
        ]}
      />
      <Typography
        variant="h1"
        gutterBottom={true}
        classes={{ root: classes.title }}
      >
        {fileName}
      </Typography>
      <div className={classes.popover}>
        <WorkbenchFilePopover file={file} />
      </div>
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <div style={{ float: 'right', display: 'flex', gap: 10 }}>
          <Button
            variant="secondary"
            onClick={handleOpenConvertToDraft}
            size="small"
          >
            {t_i18n('Convert to draft')}
          </Button>
          <Button
            onClick={handleOpenValidate}
            size="small"
          >
            {t_i18n('Validate this workbench')}
          </Button>
        </div>
      </Security>
      <div className="clearfix" />
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={currentTab} onChange={handleChangeTab}>
          <Tab label={`${t_i18n('Entities')} (${stixDomainObjects.length})`} />
          <Tab label={`${t_i18n('Observables')} (${stixCyberObservables.length})`} />
          <Tab
            label={`${t_i18n('Relationships')} (${stixCoreRelationships.length})`}
          />
          <Tab label={`${t_i18n('Sightings')} (${stixSightings.length})`} />
          <Tab label={`${t_i18n('Containers')} (${containers.length})`} />
        </Tabs>
      </Box>
      {currentTab === 0 && renderEntities()}
      {currentTab === 1 && renderObservables()}
      {currentTab === 2 && renderRelationships()}
      {currentTab === 3 && renderSightings()}
      {currentTab === 4 && renderContainers()}
      <DeleteDialog
        deletion={deletion}
        submitDelete={() => submitDeleteObject()}
        message={t_i18n('Do you want to remove this object?')}
      />
      <Formik
        enableReinitialize={true}
        initialValues={{
          refreshEntity: !!file.metaData.entity_id && !!file.metaData.entity,
          connector_id: connectors.length > 0 ? connectors[0].id : '',
        }}
        validationSchema={importValidation(t_i18n)}
        onSubmit={onSubmitValidate}
        onReset={handleCloseValidate}
      >
        {({ submitForm, handleReset, isSubmitting }) => (
          <Form style={{ margin: '0 0 20px 0' }}>
            <Dialog
              open={displayValidate}
              slotProps={{ paper: { elevation: 1 } }}
              keepMounted
              onClose={handleCloseValidate}
              fullWidth
            >
              <DialogTitle>{t_i18n('Validate and send for import')}</DialogTitle>
              <DialogContent>
                {!!file.metaData.entity_id && !!file.metaData.entity && (
                  <>
                    <Alert severity="info" variant="outlined">
                      <Typography>
                        {t_i18n('Having this checked means the last version of the entity linked to the workbench will be fetched from database before executing the workbench.')}
                      </Typography>
                      <Typography>
                        {t_i18n('Because by default the workbench won\'t include the updates made on the entity after the creation of the workbench.')}
                      </Typography>
                    </Alert>
                    <Field
                      component={SwitchField}
                      type="checkbox"
                      name="refreshEntity"
                      label={t_i18n('Refresh entity')}
                    />
                  </>
                )}
                <Field
                  component={SelectField}
                  variant="standard"
                  name="connector_id"
                  label={t_i18n('Connector')}
                  fullWidth
                  containerstyle={{ width: '100%' }}
                  disabled={connectors.filter((n) => n.active).length === 0}
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
                <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting || connectors.filter((n) => n.active).length === 0}
                >
                  {t_i18n('Create')}
                </Button>
              </DialogActions>
            </Dialog>
          </Form>
        )}
      </Formik>
      <Formik
        enableReinitialize={true}
        initialValues={{
          refreshEntity: !!file.metaData.entity_id && !!file.metaData.entity,
          connector_id: connectors.length > 0 ? connectors[0].id : '',
        }}
        validationSchema={importValidation(t_i18n)}
        onSubmit={onSubmitConvertToDraft}
        onReset={handleCloseConvertToDraft}
      >
        {({ submitForm, handleReset, isSubmitting }) => (
          <Form style={{ margin: '0 0 20px 0' }}>
            <Dialog
              open={displayConvertToDraft}
              slotProps={{ paper: { elevation: 1 } }}
              keepMounted
              onClose={handleCloseConvertToDraft}
              fullWidth
            >
              <DialogTitle>{t_i18n('Convert this workbench to a draft')}</DialogTitle>
              <DialogContent>
                {!!file.metaData.entity_id && !!file.metaData.entity && (
                  <>
                    <Alert severity="info" variant="outlined">
                      <Typography>
                        {t_i18n('Having this checked means the last version of the entity linked to the workbench will be fetched from database before executing the convertion.')}
                      </Typography>
                      <Typography>
                        {t_i18n('Because by default the draft won\'t include the updates made on the entity after the creation of the workbench.')}
                      </Typography>
                    </Alert>
                    <Field
                      component={SwitchField}
                      type="checkbox"
                      name="refreshEntity"
                      label={t_i18n('Refresh entity')}
                    />
                  </>
                )}
                <Field
                  component={SelectField}
                  variant="standard"
                  name="connector_id"
                  label={t_i18n('Connector')}
                  fullWidth
                  containerstyle={{ width: '100%' }}
                  disabled={connectors.filter((n) => n.active).length === 0}
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
                <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  // color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting || connectors.filter((n) => n.active).length === 0}
                >
                  {t_i18n('Create')}
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
          file_markings
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
