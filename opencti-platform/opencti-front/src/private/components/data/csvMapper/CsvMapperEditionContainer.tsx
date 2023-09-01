import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import CsvMapperEdition from '@components/data/csvMapper/CsvMapperEdition';
import {
  CsvMapperEditionContainerFragment_csvMapper$key,
} from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerFragment_csvMapper.graphql';
import {
  CsvMapperEditionContainerQuery,
} from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerQuery.graphql';
import Drawer from '@components/common/drawer/Drawer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';

const csvMapperEditionContainerFragment = graphql`
  fragment CsvMapperEditionContainerFragment_csvMapper on CsvMapper {
    id
    name
    has_header
    separator
    errors
    representations {
      id
      type
      target {
        entity_type
      }
      attributes {
        key
        column {
          column_name
        }
        based_on {
          representations
        }
      }
    }
  }
`;

export const csvMapperEditionContainerQuery = graphql`
  query CsvMapperEditionContainerQuery($id: String!) {
    csvMapper(id: $id) {
      ...CsvMapperEditionContainerFragment_csvMapper
    }
  }
`;

interface CsvMapperEditionProps {
  queryRef: PreloadedQuery<CsvMapperEditionContainerQuery>;
  open: boolean;
  onClose?: () => void;
}

const CsvMapperEditionContainer: FunctionComponent<CsvMapperEditionProps> = ({
  queryRef,
  open,
  onClose,
}) => {
  const { t } = useFormatter();

  const data = usePreloadedQuery(csvMapperEditionContainerQuery, queryRef);
  const csvMapper = useFragment<CsvMapperEditionContainerFragment_csvMapper$key>(csvMapperEditionContainerFragment, data.csvMapper);

  if (!csvMapper) {
    return <Loader variant={LoaderVariant.inElement} />;
  }

  return (
    <Drawer
      title={t('Csv Mapper edition')}
      open={open}
      onClose={onClose}
    >
      <CsvMapperEdition csvMapper={csvMapper} onClose={onClose}/>
    </Drawer>
  );
};

export default CsvMapperEditionContainer;
