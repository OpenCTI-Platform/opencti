import React from 'react';
import { DataColumns } from '../../../../components/list_lines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import SettingsMessagesLine, { SettingsMessagesLineDummy } from './SettingsMessagesLine';
import { SettingsMessagesLine_settingsMessage$key } from './__generated__/SettingsMessagesLine_settingsMessage.graphql';

const SettingsMessagesLines = ({
  settingsId,
  datas,
  dataColumns,
}: {
  settingsId: string,
  datas: { node: SettingsMessagesLine_settingsMessage$key }[]
  dataColumns: DataColumns,
}) => {
  return (
    <ListLinesContent
      initialLoading={false}
      loadMore={() => {}}
      hasMore={() => {}}
      isLoading={() => false}
      dataList={datas}
      globalCount={datas.length}
      LineComponent={SettingsMessagesLine}
      DummyLineComponent={SettingsMessagesLineDummy}
      dataColumns={dataColumns}
      entityId={settingsId}
    />
  );
};

export default SettingsMessagesLines;
