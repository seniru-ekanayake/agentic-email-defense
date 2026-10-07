import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'FishingMails • Email Threat Investigation',
  description: 'Evidence-based email threat triage with analyst-approved response',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
        <link rel="stylesheet" href="/tailwind.css" />
      </head>
      <body className="antialiased bg-[#f7f8fa] text-[#111318] font-sans selection:bg-blue-500/20 selection:text-blue-600">
        {children}
      </body>
    </html>
  );
}
