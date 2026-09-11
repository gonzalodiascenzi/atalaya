// ATALAYA // CloudFront Function (viewer-request) en /api/* y /health*.
//
// Escribe la IP real del cliente en `x-atalaya-ip`, sacada de la conexión
// que vio CloudFront. La PISA si el cliente mandó una propia: lo que escribe
// el cliente no vale nada. La API la usa para el limitador de tasa, porque
// detrás de Lambda X-Forwarded-For queda reducida al valor que escribe el
// cliente (ver `_client_ip` en src/api/main.py).
function handler(event) {
  var request = event.request;
  request.headers['x-atalaya-ip'] = { value: event.viewer.ip };
  return request;
}
