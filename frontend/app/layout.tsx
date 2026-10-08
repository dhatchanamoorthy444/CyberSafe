import { Inter } from 'next/font/google';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata = {
  title: 'CyberSafe | Zero-Trust Threat Intelligence',
  description: 'Real-time URL and phishing threat intelligence',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-[#0F172A] text-white antialiased`}>
        {children}
      </body>
    </html>
  );
}
