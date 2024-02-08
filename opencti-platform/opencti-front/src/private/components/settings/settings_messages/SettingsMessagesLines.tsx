import React, { MutableRefObject } from 'react';
import { GridTypeMap } from '@mui/material';
import { DataColumns } from '../../../../components/list_lines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import SettingsMessagesLine, { SettingsMessagesLineDummy } from './SettingsMessagesLine';
import { SettingsMessagesLine_settingsMessage$key } from './__generated__/SettingsMessagesLine_settingsMessage.graphql';

const SettingsMessagesLines = ({
  settingsId,
  datas,
  dataColumns,
  containerRef,
}: {
  settingsId: string,
  datas: { node: SettingsMessagesLine_settingsMessage$key }[]
  dataColumns: DataColumns,
  containerRef: MutableRefObject<GridTypeMap | null>;
}) => {
  return (
    <ListLinesContent
      initialLoading={false}
      isLoading={() => false}
      loadMore={() => null}
      hasMore={() => false}
      dataList={datas ?? []}
      globalCount={datas.length ?? 1}
      nbOfRowsToLoad={50}
      LineComponent={SettingsMessagesLine}
      DummyLineComponent={SettingsMessagesLineDummy}
      dataColumns={dataColumns}
      entityId={settingsId}
      containerRef={containerRef}
    />
  );
};

export default SettingsMessagesLines;
