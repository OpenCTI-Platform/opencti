import React, { ReactNode } from 'react';
import { AutoSizer, List, ListRowProps } from 'react-virtualized';

const DEFAULT_ROW_HEIGHT = 57;
const DEFAULT_MAX_VISIBLE_ROWS = 10;

interface SecurityCoverageCoveredListProps<T> {
  entities: ReadonlyArray<T>;
  rowRenderer: (entity: T) => ReactNode;
  rowHeight?: number;
  maxVisibleRows?: number;
  style?: React.CSSProperties;
}

const SecurityCoverageCoveredList = <T,>({
  entities,
  rowRenderer,
  rowHeight = DEFAULT_ROW_HEIGHT,
  maxVisibleRows = DEFAULT_MAX_VISIBLE_ROWS,
  style,
}: SecurityCoverageCoveredListProps<T>) => {
  const rowCount = entities.length;
  const height = Math.min(rowCount, maxVisibleRows) * rowHeight;
  const virtualizedRowRenderer = ({ index, key, style: rowStyle }: ListRowProps) => (
    <div key={key} style={rowStyle}>
      {rowRenderer(entities[index])}
    </div>
  );
  return (
    <div style={{ height, width: '100%', ...style }}>
      <AutoSizer disableHeight>
        {({ width }) => (
          <List
            width={width}
            height={height}
            rowCount={rowCount}
            rowHeight={rowHeight}
            rowRenderer={virtualizedRowRenderer}
            overscanRowCount={5}
          />
        )}
      </AutoSizer>
    </div>
  );
};

export default SecurityCoverageCoveredList;
