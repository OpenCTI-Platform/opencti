import React from 'react';
import ItemNumberDifference from '../ItemNumberDifference';
import { useFormatter } from '../i18n';

interface WidgetNumberProps {
  count: number
  change: number,
  interval: string
}

const WidgetNumber = ({ count, change, interval }: WidgetNumberProps) => {
  const { t_i18n, n } = useFormatter();

  return (
    <>
      <div style={{ float: 'left', fontSize: 40 }}>
        {n(count)}
      </div>
      <ItemNumberDifference
        difference={change}
        description={t_i18n(`From previous ${interval}`)}
      />
    </>
  );
};

export default WidgetNumber;
