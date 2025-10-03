// Default coordinates (Paris) for fallback when coordinates are invalid
export const DEFAULT_CENTER_COORDINATES: [number, number] = [48.8566969, 2.3514616];

// Validate latitude is within valid range
export const isValidLatitude = (lat: number | null | undefined): boolean => {
  return lat !== null && lat !== undefined && lat >= -90 && lat <= 90;
};

// Validate longitude is within valid range
export const isValidLongitude = (lng: number | null | undefined): boolean => {
  return lng !== null && lng !== undefined && lng >= -180 && lng <= 180;
};

// Get validated coordinates, fallback to default if invalid
export const getValidatedCenter = (position: { latitude?: number | null; longitude?: number | null }): [number, number] => {
  if (isValidLatitude(position.latitude) && isValidLongitude(position.longitude)) {
    return [position.latitude as number, position.longitude as number];
  }
  return DEFAULT_CENTER_COORDINATES;
};

// Validate coordinate array format
export const validateCoordinates = (coordinates: unknown): [number, number] => {
  if (!coordinates || !Array.isArray(coordinates) || coordinates.length !== 2) {
    return DEFAULT_CENTER_COORDINATES;
  }
  const [lat, lng] = coordinates;
  if (!isValidLatitude(lat) || !isValidLongitude(lng)) {
    return DEFAULT_CENTER_COORDINATES;
  }
  return [lat, lng] as [number, number];
};
