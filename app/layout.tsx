import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Neyla Haroune — Portfolio",
  description: "Étudiante en L3 Informatique à Rennes. Candidate en Master Informatique.",
  openGraph: {
    title: "Neyla Haroune — Portfolio",
    description: "Projets en circuits numériques, C++, Flask, web.",
    type: "website",
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="fr">
      <body>{children}</body>
    </html>
  );
}
