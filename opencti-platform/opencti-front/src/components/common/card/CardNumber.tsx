import Card from './Card';
import WidgetNumber, { WidgetNumberProps } from '../../dashboard/WidgetNumber';

type CardNumberProps = WidgetNumberProps;

const CardNumber = (props: CardNumberProps) => {
  return (
    <Card sx={{ paddingY: 2 }}>
      <WidgetNumber {...props} />
    </Card>
  );
};

export default CardNumber;
