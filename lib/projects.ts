export interface Project {
  id: string;
  year: string;
  type: string;
  title: string;
  subtitle: string;
  description: string;
  tags: string[];
  color: string; // accent color for the card
  image?: string; // path in /public
  highlights: string[];
}

export const projects: Project[] = [
  {
    id: "yemma",
    year: "2026",
    type: "Projet personnel",
    title: "Restaurant Yemma",
    subtitle: "App de gestion de réservations",
    description:
      "Application web complète pour un restaurant : gestion des flux clients, automatisation des e-mails de confirmation, interface responsive. Développée de A à Z en solo.",
    tags: ["Python", "Flask", "Flask-Mail", "JavaScript", "HTML/CSS"],
    color: "#D4A85A",
    highlights: [
      "Gestion des réservations en temps réel",
      "Envoi automatique d'e-mails de confirmation",
      "Interface responsive mobile-first",
    ],
  },
  {
    id: "circuits",
    year: "2025–2026",
    type: "Académique · L3 PFO",
    title: "Circuits Numériques",
    subtitle: "Conception matérielle & FSM",
    description:
      "Série de 4 TPs de conception matérielle sur Logisim-Evolution : montre numérique 24h (BCD), multiplieur/diviseur 8 bits avec algorithme conçu de zéro, machines à états finis, récepteur série avec détection de parité.",
    tags: ["Logisim-Evolution", "FSM", "BCD", "Arithmétique binaire", "REQ/ACK"],
    color: "#7A9CCC",
    highlights: [
      "Montre numérique 24h avec afficheurs BCD",
      "Multiplieur/Diviseur 8 bits (UT + UC)",
      "Récepteur série & détection d'erreur de parité",
    ],
  },
  {
    id: "rami-site",
    year: "2024",
    type: "Académique · L1 Angers",
    title: "Site Vitrine Rami",
    subtitle: "Site web multi-pages",
    description:
      "Site web accompagnant le projet Rami : présentation des règles, explication de l'algorithme C++, page membres. Animations CSS au scroll, navigation fluide entre pages.",
    tags: ["HTML", "CSS", "JavaScript", "Responsive", "Animations CSS"],
    color: "#A8C67A",
    highlights: [
      "3 pages interconnectées",
      "Animations au scroll",
      "Design beige chaleureux",
    ],
  },
  {
    id: "rami-cpp",
    year: "2024",
    type: "Académique · L1 Angers",
    title: "Jeu de Rami",
    subtitle: "Moteur de jeu en C++",
    description:
      "Développement complet d'un jeu de Rami en C++. Logique métier entière : création et mélange du jeu, distribution, détection des brelans/suites/carrés, gestion de la défausse et suggestions de jeu.",
    tags: ["C++", "Listes chaînées", "Algorithmique", "Logique métier"],
    color: "#CC8A7A",
    highlights: [
      "Détection automatique des combinaisons",
      "Gestion de la défausse avec suggestions",
      "Structures de données personnalisées",
    ],
  },
];
