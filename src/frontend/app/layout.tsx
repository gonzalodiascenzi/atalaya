import type { Metadata, Viewport } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'ATALAYA // CTI OPS',
  description:
    'Academia táctica de ciberseguridad basada en inteligencia de amenazas real. ' +
    'El que vigila desde arriba ve venir la amenaza primero.',
  applicationName: 'ATALAYA',
  keywords: ['CTI', 'threat intelligence', 'STIX 2.1', 'MISP', 'OpenCTI', 'SOC'],
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: '#05070a',
  colorScheme: 'dark',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="es-AR" className="dark">
      {/* `crt` inyecta las líneas de barrido y el haz que recorre la pantalla. */}
      <body className="crt min-h-screen">{children}</body>
    </html>
  );
}
