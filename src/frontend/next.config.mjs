// Dos formas de salida, según dónde corra la consola:
//   · standalone → servidor Node en Docker/Compose, que agrega él mismo las
//     cabeceras de seguridad (ver headers() abajo).
//   · export     → HTML estático para S3 + CloudFront. No hay servidor, así
//     que las cabeceras las pone CloudFront (infra/terraform/cdn.tf).
const EXPORT_ESTATICO = process.env.NEXT_OUTPUT === 'export';

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: EXPORT_ESTATICO ? 'export' : 'standalone',
  // No filtramos la versión del framework en las cabeceras.
  poweredByHeader: false,

  // headers() no existe en un export estático: Next falla si se declara.
  ...(EXPORT_ESTATICO ? {} : { headers: cabeceras }),
};

async function cabeceras() {
    // Cabeceras de seguridad. La CSP es restrictiva a propósito: esta consola
    // renderiza datos que vienen de fuentes no confiables (feeds OSINT).
    const csp = [
      "default-src 'self'",
      // 'unsafe-inline' en styles es requisito del runtime de Next;
      // en scripts sólo se habilita en desarrollo para el hot reload.
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com data:",
      // 'unsafe-inline' también en producción. El App Router incrusta 7
      // scripts en línea (`self.__next_f.push(...)`) para hidratar la página:
      // con `script-src 'self'` a secas el navegador los bloquea y la consola
      // no arranca. Así estuvo desde el primer día sin que se viera, porque
      // sólo se probaba en desarrollo. El riesgo se acota porque React escapa
      // todo lo que renderiza y el contenido de los feeds OSINT se muestra
      // como texto, nunca como HTML. La alternativa estricta son nonces por
      // pedido, que obligan a renderizar en el servidor cada vez.
      process.env.NODE_ENV === 'development'
        ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
        : "script-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      `connect-src 'self' ${process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000'}`,
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; ');

    return [
      {
        source: '/:path*',
        headers: [
          { key: 'Content-Security-Policy', value: csp },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
          {
            key: 'Permissions-Policy',
            value: 'geolocation=(), microphone=(), camera=()',
          },
        ],
      },
    ];
}

export default nextConfig;
