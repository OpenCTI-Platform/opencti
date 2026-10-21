import React, { ReactNode } from 'react';
import { List, RowRendererParams } from 'react-virtualized';
import { AutoSizer } from 'react-virtualized-auto-sizer';

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
  const virtualizedRowRenderer = ({ index, key, style: rowStyle }: RowRendererParams) => (
    <div key={key} style={rowStyle}>
      {rowRenderer(entities[index])}
    </div>
  );
  return (
    <div style={{ height, width: '100%', ...style }}>
      <AutoSizer
        renderProp={({ width }) => (width ? (
          <List
            role="grid"
            width={width}
            height={height}
            rowCount={rowCount}
            rowHeight={rowHeight}
            rowRenderer={virtualizedRowRenderer}
            overscanRowCount={5}
          />
        ) : null)}
      />
    </div>
  );
};

export default SecurityCoverageCoveredList;
