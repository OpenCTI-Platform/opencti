import React, { Key, ReactNode, useState } from 'react';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';

// A list of thousands of rows (a bundle of 50 000 labels) is never mounted at once: the first rows are, and a button shows the next ones
export const CONFIG_PRESET_LIST_PAGE_SIZE = 200;

interface ConfigPresetProgressiveListProps<T> {
  items: ReadonlyArray<T>;
  getKey: (item: T) => Key;
  renderItem: (item: T) => ReactNode;
  pageSize?: number;
}

const ConfigPresetProgressiveList = <T, >({ items, getKey, renderItem, pageSize = CONFIG_PRESET_LIST_PAGE_SIZE }: ConfigPresetProgressiveListProps<T>) => {
  const { t_i18n } = useFormatter();
  // How many pages are shown, so that the list keeps its length when its items change
  const [pages, setPages] = useState(1);
  const shown = items.slice(0, pages * pageSize);
  const remaining = items.length - shown.length;
  return (
    <>
      {shown.map((item) => <React.Fragment key={getKey(item)}>{renderItem(item)}</React.Fragment>)}
      {remaining > 0 && (
        <div>
          <Button variant="tertiary" onClick={() => setPages((current) => current + 1)}>
            {`${t_i18n('Show more')} (${remaining})`}
          </Button>
        </div>
      )}
    </>
  );
};

export default ConfigPresetProgressiveList;
