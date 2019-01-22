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

export const itemColor = (type, dark) => {
  switch (type) {
    case 'sector':
      if (dark) {
        return '#0d47a1';
      }
      return '#2196f3';
    case 'threat-actor':
      if (dark) {
        return '#880e4f';
      }
      return '#e91e63';
    case 'intrusion-set':
      if (dark) {
        return '#bf360c';
      }
      return '#ff5722';
    case 'campaign':
      if (dark) {
        return '#4a148c';
      }
      return '#9c27b0';
    case 'incident':
      if (dark) {
        return '#f44336';
      }
      return '#b71c1c';
    case 'user':
      if (dark) {
        return '#006064';
      }
      return '#00BCD4';
    case 'organization':
      if (dark) {
        return '#01579b';
      }
      return '#03A9F4';
    case 'city':
      if (dark) {
        return '#004d40';
      }
      return '#009688';
    case 'country':
      if (dark) {
        return '#3f51b5';
      }
      return '#3F51B5';
    case 'attack-pattern':
      if (dark) {
        return '#827717';
      }
      return '#cddc39';
    case 'malware':
      if (dark) {
        return '#e65100';
      }
      return '#ff9800';
    case 'tool':
      if (dark) {
        return '#1b5e20';
      }
      return '#4caf50';
    case 'vulnerability':
      if (dark) {
        return '#3e2723';
      }
      return '#795548';
    default:
      if (dark) {
        return '#607d8b';
      }
      return '#263238';
  }
};
