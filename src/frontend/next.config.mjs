/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Salida autocontenida: la imagen final no necesita node_modules completo.
  output: 'standalone',
  // No filtramos la versión del framework en las cabeceras.
  poweredByHeader: false,

  async headers() {
    // Cabeceras de seguridad. La CSP es restrictiva a propósito: esta consola
    // renderiza datos que vienen de fuentes no confiables (feeds OSINT).
    const csp = [
      "default-src 'self'",
      // 'unsafe-inline' en styles es requisito del runtime de Next;
      // en scripts sólo se habilita en desarrollo para el hot reload.
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com data:",
      process.env.NODE_ENV === 'development'
        ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
        : "script-src 'self'",
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
  },
};

export default nextConfig;
