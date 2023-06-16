import React from 'react';
import { DataColumns } from '../../../../../components/list_lines';
import EntitySettingAttributeLine, { EntitySettingAttributeLineDummy } from './EntitySettingAttributeLine';
import ListLinesContent from '../../../../../components/list_lines/ListLinesContent';
import { useFormatter } from '../../../../../components/i18n';
import {
  EntitySettingAttributes_entitySetting$data,
} from './__generated__/EntitySettingAttributes_entitySetting.graphql';

interface AttributeNode {
  label: string | null,
  name: string,
  type: string,
  scale: string | null
}

export const computeAttributeNodeType = (node: AttributeNode) => {
  return !node.scale ? node.type : 'scale';
};

const EntitySettingAttributeLines = ({
  datas,
  dataColumns,
  keyword,
  entitySetting,
}: {
  datas: { node: AttributeNode }[],
  dataColumns: DataColumns,
  keyword: string | undefined,
  entitySetting: EntitySettingAttributes_entitySetting$data,
}) => {
  const { t } = useFormatter();

  const filterOn = ({ node }: { node: AttributeNode }) => {
    if (keyword) {
      const value = node.label ?? node.name;
      const filterOnValue = value.toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
      const filterOnValueTranslated = t(`${value}`).toLowerCase().indexOf(keyword.toLowerCase()) !== -1;

      const type = computeAttributeNodeType(node);
      const filterOnType = type.toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
      const filterOnTypeTranslated = t(`${type}`).toLowerCase().indexOf(keyword.toLowerCase()) !== -1;

      return filterOnValue || filterOnValueTranslated || filterOnType || filterOnTypeTranslated;
    }
    return true;
  };
  const sortOn = (
    edgeA: { node: AttributeNode },
    edgeB: { node: AttributeNode },
  ) => {
    const valueA = edgeA.node.label ?? edgeA.node.name;
    const valueB = edgeB.node.label ?? edgeB.node.name;
    return t(`${valueA}`).localeCompare(t(`${valueB}`));
  };

  const attributes = (datas ?? [])
    .filter(filterOn)
    .sort(sortOn);

  return (
    <ListLinesContent
      initialLoading={false}
      loadMore={() => {}}
      hasMore={() => {}}
      isLoading={() => false}
      dataList={attributes}
      globalCount={attributes.length}
      LineComponent={<EntitySettingAttributeLine entitySetting={entitySetting} />}
      DummyLineComponent={EntitySettingAttributeLineDummy}
      dataColumns={dataColumns}
    />
  );
};

export default EntitySettingAttributeLines;
