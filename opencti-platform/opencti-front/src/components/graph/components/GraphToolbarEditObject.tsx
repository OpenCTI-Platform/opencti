import { EditOutlined } from '@mui/icons-material';
import React, { useState } from 'react';
import StixDomainObjectEdition from '@components/common/stix_domain_objects/StixDomainObjectEdition';
import StixCyberObservableEdition from '@components/observations/stix_cyber_observables/StixCyberObservableEdition';
import StixCoreRelationshipEdition from '@components/common/stix_core_relationships/StixCoreRelationshipEdition';
import StixSightingRelationshipEdition from '@components/events/stix_sighting_relationships/StixSightingRelationshipEdition';
import StixNestedRefRelationshipEdition from '@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipEdition';
import { GraphQLTaggedNode } from 'relay-runtime/lib/query/RelayModernGraphQLTag';
import GraphToolbarItem from './GraphToolbarItem';
import { useFormatter } from '../../i18n';
import { useGraphContext } from '../GraphContext';
import type { GraphNode, GraphLink } from '../graph.types';
import { isStixNestedRefRelationship } from '../../../utils/Relation';
import { fetchQuery } from '../../../relay/environment';
import useGraphInteractions from '../utils/useGraphInteractions';
import { ObjectToParse } from '../utils/useGraphParser';

interface GraphToolbarEditObjectProps {
  stixCoreObjectRefetchQuery: GraphQLTaggedNode
  relationshipRefetchQuery: GraphQLTaggedNode
}

type EditionCategory = 'domainObject' | 'observable' | 'relation' | 'sighting' | 'nested';

const GraphToolbarEditObject = ({
  stixCoreObjectRefetchQuery,
  relationshipRefetchQuery,
}: GraphToolbarEditObjectProps) => {
  const { t_i18n } = useFormatter();
  const { addNode, addLink } = useGraphInteractions();

  const {
    graphState: {
      selectedNodes,
      selectedLinks,
    },
  } = useGraphContext();

  const [category, setCategory] = useState<EditionCategory>();

  let objectToEdit: GraphNode | GraphLink | undefined;
  if (selectedNodes.length === 1 && !selectedNodes[0].isNestedInferred) {
    [objectToEdit] = selectedNodes;
  } else if (selectedLinks.length === 1 && (!selectedLinks[0].inferred || !selectedLinks[0].isNestedInferred)) {
    [objectToEdit] = selectedLinks;
  }

  const openEditionForm = () => {
    if (!objectToEdit) return;
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
        addNode(data.stixCoreObject);
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
        disabled={!objectToEdit}
        color="primary"
        onClick={openEditionForm}
        title={t_i18n('Edit the selected item')}
      />
      {objectToEdit && (
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
            inGraph
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
            handleDelete={null}
            stixSightingRelationshipId={objectToEdit.id}
            handleClose={closeEditionForm}
          />
          <StixNestedRefRelationshipEdition
            noStoreUpdate
            open={category === 'nested'}
            stixNestedRefRelationshipId={objectToEdit.id}
            handleClose={closeEditionForm}
          />
        </>
      )}
    </>
  );
};

export default GraphToolbarEditObject;
