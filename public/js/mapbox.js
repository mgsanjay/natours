export const displayMap = (locations) => {
  mapboxgl.accessToken =
    'pk.eyJ1Ijoic2FuamF5LW0tZyIsImEiOiJja3ZybWRzbDkxa3QxMnBxaGx5Mnd2Mm5wIn0.6pHLSxOpmmmDewsR3A63_A';

  var map = new mapboxgl.Map({
    container: 'map',
    style: 'mapbox://styles/sanjay-m-g/ckvrnhzdq08my14qnr2rle5or',
    scrollZoom: false,
    //   center: [],
    //   zoom: 10,
    //   interactive: false,
  });

  const bounds = new mapboxgl.LngLatBounds();

  locations.forEach((loc) => {
    //Create marker it is a css style with image in css file with marker as class name
    const el = document.createElement('div');
    el.className = 'marker';

    //Add marker
    new mapboxgl.Marker({
      element: el,
      anchor: 'bottom',
    })
      .setLngLat(loc.coordinates)
      .addTo(map);

    //Add popup
    new mapboxgl.Popup({
      offset: 30,
    })
      .setLngLat(loc.coordinates)
      .setHTML(`<p>Day ${loc.day}: ${loc.description}</p>`)
      .addTo(map);

    //Extend map bounds to include current location
    bounds.extend(loc.coordinates);
  });

  map.fitBounds(bounds, {
    padding: {
      top: 200,
      bottom: 150,
      left: 100,
      right: 100,
    },
  });
};
