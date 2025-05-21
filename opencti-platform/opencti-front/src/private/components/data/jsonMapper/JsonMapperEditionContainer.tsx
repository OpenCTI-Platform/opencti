import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import JsonMapperEdition from '@components/data/jsonMapper/JsonMapperEdition';
import Drawer from '@components/common/drawer/Drawer';
import { JsonMapperEditionContainerQuery } from '@components/data/jsonMapper/__generated__/JsonMapperEditionContainerQuery.graphql';
import { JsonMapperEditionContainerFragment_jsonMapper$key } from '@components/data/jsonMapper/__generated__/JsonMapperEditionContainerFragment_jsonMapper.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';

export const jsonMapperEditionContainerFragment = graphql`
  fragment JsonMapperEditionContainerFragment_jsonMapper on JsonMapper {
    id
    name
    errors
    representations {
      id
      type
      target {
        path
        entity_type
      }
      identifier
      attributes {
        key
        mode
        attr_path {
          path
          configuration {
            pattern_date
            separator
            timezone
          }
          independent
        }
        complex_path {
          formula
          variables {
            path
            variable
            independent
          }
        }
        default_values {
          id
          name
        }
        based_on {
          identifier
          representations
        }
      }
    }
  }
`;

export const jsonMapperEditionContainerQuery = graphql`
  query JsonMapperEditionContainerQuery($id: ID!) {
    jsonMapper(id: $id) {
      ...JsonMapperEditionContainerFragment_jsonMapper
    }
  }
`;

interface JsonMapperEditionProps {
  queryRef: PreloadedQuery<JsonMapperEditionContainerQuery>;
  open: boolean;
  onClose?: () => void;
}

const JsonMapperEditionContainer: FunctionComponent<JsonMapperEditionProps> = ({
  queryRef,
  open,
  onClose,
}) => {
  const { t_i18n } = useFormatter();

  const data = usePreloadedQuery(jsonMapperEditionContainerQuery, queryRef);
  const jsonMapper = useFragment<JsonMapperEditionContainerFragment_jsonMapper$key>(
    jsonMapperEditionContainerFragment,
    data.jsonMapper,
  );
  if (!jsonMapper) {
    return <Loader variant={LoaderVariant.inline}/>;
  }

  return (
    <Drawer title={t_i18n('JSON Mapper edition')} open={open} onClose={onClose}>
      <JsonMapperEdition jsonMapper={jsonMapper} onClose={onClose}/>
    </Drawer>
  );
};

export default JsonMapperEditionContainer;
