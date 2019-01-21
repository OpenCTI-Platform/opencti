const colors = [
  '#EF5350',
  '#AB47BC',
  '#EC407A',
  '#7E57C2',
  '#5C6BC0',
  '#42A5F5',
  '#26A69A',
  '#66BB6A',
];

export const pickColor = index => colors[index];

export const stringToColour = (str) => {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  let colour = '#';
  for (let i = 0; i < 3; i++) {
    const value = (hash >> (i * 8)) & 0xFF;
    colour += (`00${value.toString(16)}`).substr(-2);
  }
  return colour;
};

export const itemColor = (type, opacity) => {
  switch (type) {
    case 'sector':
      if (opacity === 1) {
        return '#1565c0';
      }
      return `rgba(21, 101, 192, ${opacity})`;

    case 'threat-actor':
      if (opacity === 1) {
        return '#ad1457';
      }
      return `rgba(173, 20, 87, ${opacity})`;

    case 'intrusion-set':
      if (opacity === 1) {
        return '#d84315';
      }
      return `rgba(216, 67, 21, ${opacity})`;

    case 'campaign':
      if (opacity === 1) {
        return '#9C27B0';
      }
      return `rgba(156, 39, 176, ${opacity})`;

    case 'incident':
      if (opacity === 1) {
        return '#F44336';
      }
      return `rgba(244, 67, 54, ${opacity})`;

    case 'user':
      if (opacity === 1) {
        return '#00BCD4';
      }
      return `rgba(0, 188, 212, ${opacity})`;

    case 'organization':
      if (opacity === 1) {
        return '#03A9F4';
      }
      return `rgba(3, 169, 244, ${opacity})`;

    case 'city':
      if (opacity === 1) {
        return '#009688';
      }
      return `rgba(0, 150, 136, ${opacity})`;

    case 'country':
      if (opacity === 1) {
        return '#3F51B5';
      }
      return `rgba(63, 81, 181, ${opacity})`;

    case 'attack-pattern':
      if (opacity === 1) {
        return '#CDDC39';
      }
      return `rgba(205, 220, 57, ${opacity})`;

    case 'malware':
      if (opacity === 1) {
        return '#FFB300';
      }
      return `rgba(255, 179, 0, ${opacity})`;

    case 'tool':
      if (opacity === 1) {
        return '#4CAF50';
      }
      return `rgba(76, 175, 80, ${opacity})`;

    case 'vulnerability':
      if (opacity === 1) {
        return '#795548';
      }
      return `rgba(121, 85, 72, ${opacity})`;

    default:
      if (opacity === 1) {
        return '#FFFFFF';
      }
      return `rgba(255, 255, 255, ${opacity})`;
  }
};
