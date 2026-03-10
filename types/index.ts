export interface ProjectModal {
  details: string[];
  downloadLabel: string;
  downloadHref: string;
  externalLink?: string;
  externalLabel?: string;
}

export interface Project {
  id: string;
  title: string;
  subtitle: string;
  year: string;
  type: "personnel" | "académique";
  description: string;
  longDescription: string;
  tags: string[];
  image: string;
  accentColor: string;
  modal: ProjectModal;
  links?: { label: string; href: string }[];
}
