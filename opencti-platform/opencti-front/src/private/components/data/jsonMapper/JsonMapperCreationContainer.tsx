import React, { FunctionComponent } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import JsonMapperCreation from '@components/data/jsonMapper/JsonMapperCreation';
import { jsonMappers_MappersQuery$variables } from '@components/data/jsonMapper/__generated__/jsonMappers_MappersQuery.graphql';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { jsonMapperEditionContainerQuery } from '@components/data/jsonMapper/JsonMapperEditionContainer';
import { JsonMapperEditionContainerQuery } from '@components/data/jsonMapper/__generated__/JsonMapperEditionContainerQuery.graphql';
import { useFormatter } from '../../../../components/i18n';

interface JsonMapperCreationProps {
  paginationOptions: jsonMappers_MappersQuery$variables;
  editionQueryRef?: PreloadedQuery<JsonMapperEditionContainerQuery>,
  isDuplicated?: boolean;
  onClose?: () => void;
  open: boolean;
}

const JsonMapperCreationContainer: FunctionComponent<JsonMapperCreationProps> = ({
  editionQueryRef,
  onClose,
  isDuplicated,
  open,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const mappingJson = editionQueryRef ? (usePreloadedQuery(jsonMapperEditionContainerQuery, editionQueryRef)).jsonMapper : null;
  return (
    <Drawer
      title={isDuplicated ? t_i18n('Duplicate a JSON mapper') : t_i18n('Create a JSON mapper')}
      open={open}
      onClose={onClose}
    >
      <JsonMapperCreation
        mappingJson={mappingJson}
        paginationOptions={paginationOptions}
        onClose={onClose}
        isDuplicated={isDuplicated}
      />
    </Drawer>
  );
};

export default JsonMapperCreationContainer;
