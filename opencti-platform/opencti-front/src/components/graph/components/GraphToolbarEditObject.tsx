import { EditOutlined } from '@mui/icons-material';
import React, { useState } from 'react';
import StixDomainObjectEdition from '@components/common/stix_domain_objects/StixDomainObjectEdition';
import StixCyberObservableEdition from '@components/observations/stix_cyber_observables/StixCyberObservableEdition';
import StixCoreRelationshipEdition from '@components/common/stix_core_relationships/StixCoreRelationshipEdition';
import StixSightingRelationshipEdition from '@components/events/stix_sighting_relationships/StixSightingRelationshipEdition';
import StixNestedRefRelationshipEdition from '@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipEdition';
import type { GraphQLTaggedNode } from 'relay-runtime';
import GraphToolbarItem from './GraphToolbarItem';
import { useFormatter } from '../../i18n';
import { useGraphContext } from '../GraphContext';
import { type GraphNode, type GraphLink, isInferredLink, isInferredNode } from '../graph.types';
import { isStixNestedRefRelationship } from '../../../utils/Relation';
import { fetchQuery } from '../../../relay/environment';
import useGraphInteractions from '../utils/useGraphInteractions';
import { ObjectToParse } from '../utils/useGraphParser';

interface GraphToolbarEditObjectProps {
  stixCoreObjectRefetchQuery: GraphQLTaggedNode;
  relationshipRefetchQuery: GraphQLTaggedNode;
}

type EditionCategory = 'domainObject' | 'observable' | 'relation' | 'sighting' | 'nested';

const GraphToolbarEditObject = ({
  stixCoreObjectRefetchQuery,
  relationshipRefetchQuery,
}: GraphToolbarEditObjectProps) => {
  const { t_i18n } = useFormatter();
  const { updateNode, addLink } = useGraphInteractions();

  const {
    rawObjects,
    graphState: {
      selectedNodes,
      selectedLinks,
    },
  } = useGraphContext();

  const [category, setCategory] = useState<EditionCategory>();

  const single = selectedNodes.length + selectedLinks.length === 1;
  let objectToEdit: GraphNode | GraphLink | undefined;
  if (single && selectedNodes.length === 1 && !isInferredNode(selectedNodes[0])) {
    [objectToEdit] = selectedNodes;
  } else if (single && selectedLinks.length === 1 && !isInferredLink(selectedLinks[0])) {
    [objectToEdit] = selectedLinks;
  }
  const isNotEditableFromGraph = !!objectToEdit
    && (objectToEdit.parent_types.includes('Stix-Meta-Object')
      || objectToEdit.parent_types.includes('Internal-Object')
      || objectToEdit.parent_types.includes('internal-relationship'));
  let editDisabledReason: string | undefined;
  if (!objectToEdit) {
    editDisabledReason = single
      ? t_i18n('Inferred knowledge cannot be edited')
      : t_i18n('Select one entity or relationship first');
  } else if (isNotEditableFromGraph) {
    editDisabledReason = t_i18n("This item can't be edited from the graph");
  }

  const openEditionForm = () => {
    if (!objectToEdit || isNotEditableFromGraph) return;
    const { parent_types, entity_type } = objectToEdit;
    if (!parent_types.includes('basic-relationship')
      && !parent_types.includes('Stix-Cyber-Observable')) {
      setCategory('domainObject');
    } else if (parent_types.includes('Stix-Cyber-Observable')) {
      setCategory('observable');
    } else if (parent_types.includes('stix-core-relationship')) {
      setCategory('relation');
    } else if (entity_type === 'stix-sighting-relationship') {
      setCategory('sighting');
    } else if (parent_types.some((el) => isStixNestedRefRelationship(el))) {
      setCategory('nested');
    }
  };

  const closeEditionForm = async () => {
    if (objectToEdit) {
      if (category === 'domainObject' || category === 'observable') {
        const data = await fetchQuery(stixCoreObjectRefetchQuery, { id: objectToEdit.id })
          .toPromise() as { stixCoreObject: ObjectToParse };
        const existingNode = rawObjects.find((rawObject) => rawObject.id === objectToEdit.id);
        updateNode({ ...data.stixCoreObject, linkedContainers: existingNode?.linkedContainers ?? [] });
      } else {
        const data = await fetchQuery(relationshipRefetchQuery, { id: objectToEdit.id })
          .toPromise() as { stixRelationship: ObjectToParse };
        addLink(data.stixRelationship);
      }
    }
    setCategory(undefined);
  };

  return (
    <>
      <GraphToolbarItem
        Icon={<EditOutlined />}
        disabledReason={editDisabledReason}
        color="primary"
        onClick={openEditionForm}
        title={t_i18n('Edit the selected item')}
      />
      {objectToEdit && !isNotEditableFromGraph && (
        <>
          <StixDomainObjectEdition
            noStoreUpdate
            open={category === 'domainObject'}
            stixDomainObjectId={objectToEdit.id}
            handleClose={closeEditionForm}
          />
          <StixCyberObservableEdition
            open={category === 'observable'}
            stixCyberObservableId={objectToEdit.id}
            handleClose={closeEditionForm}
          />
          <StixCoreRelationshipEdition
            noStoreUpdate
            open={category === 'relation'}
            stixCoreRelationshipId={objectToEdit.id}
            handleClose={closeEditionForm}
          />
          <StixSightingRelationshipEdition
            inGraph
            noStoreUpdate
            open={category === 'sighting'}
            inferred={false}
            stixSightingRelationshipId={objectToEdit.id}
            handleClose={closeEditionForm}
          />
          {category === 'nested' && (
            <StixNestedRefRelationshipEdition
              open={category === 'nested'}
              stixNestedRefRelationshipId={objectToEdit.id}
              handleClose={closeEditionForm}
            />
          )}
        </>
      )}
    </>
  );
};

export default GraphToolbarEditObject;
