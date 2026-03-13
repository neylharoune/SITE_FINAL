"use client";
import { useRef, useState, useEffect } from "react";
import { motion, useInView } from "framer-motion";
import Image from "next/image";
import type { Project } from "@/types";
import ProjectModal from "./ProjectModal";

interface Props { projects: Project[] }

function Tag({ label }: { label: string }) {
  return (
    <span className="text-[0.65rem] font-medium tracking-[0.05em] px-2.5 py-1 rounded-full"
      style={{ background: "#FAF0F4", color: "#B08090", border: "1px solid #EDD5DC" }}>
      {label}
    </span>
  );
}

function ProjectCard({ project, index, onClick }: { project: Project; index: number; onClick: () => void }) {
  const [hovered, setHovered] = useState(false);
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-60px" });

  return (
    <motion.article
      ref={ref}
      initial={{ opacity: 0, y: 28 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.65, delay: index * 0.12, ease: [0.22, 1, 0.36, 1] }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onClick={onClick}
      className="relative flex-shrink-0 w-[320px] md:w-[360px] rounded-2xl overflow-hidden cursor-pointer"
      style={{
        background: "#FFFFFF",
        border: "1px solid #EDD5DC",
        boxShadow: hovered ? "0 20px 60px rgba(196,116,138,0.15)" : "0 4px 20px rgba(61,32,48,0.06)",
        transition: "box-shadow 0.35s ease, transform 0.35s ease",
        transform: hovered ? "translateY(-8px)" : "translateY(0)",
      }}
    >
      {/* Image */}
      <div className="relative w-full h-[180px] overflow-hidden" style={{ background: "#FAF0F4" }}>
        <Image src={project.image} alt={project.title} fill
          className="object-cover transition-transform duration-700"
          style={{ transform: hovered ? "scale(1.05)" : "scale(1)" }}
        />
        <div className="absolute inset-0"
          style={{ background: "linear-gradient(to bottom, transparent 50%, rgba(255,255,255,0.9) 100%)" }} />

        <div className="absolute top-3 left-3">
          <span className="text-[0.62rem] font-semibold tracking-[0.1em] uppercase px-3 py-1 rounded-full"
            style={{
              background: project.type === "personnel" ? "#C4748A" : "rgba(255,255,255,0.92)",
              color: project.type === "personnel" ? "#fff" : "#B08090",
              border: project.type !== "personnel" ? "1px solid #EDD5DC" : "none",
              backdropFilter: "blur(8px)",
            }}>
            {project.type === "personnel" ? "✦ Perso" : "Académique"}
          </span>
        </div>
        <div className="absolute top-3 right-3 text-[0.62rem] font-medium tracking-wider"
          style={{ color: "rgba(61,32,48,0.4)" }}>{project.year}</div>
      </div>

      {/* Content */}
      <div className="p-5 flex flex-col gap-2.5">
        <div>
          <p className="text-[0.66rem] font-medium tracking-[0.14em] uppercase mb-0.5 text-accent">{project.subtitle}</p>
          <h3 className="font-serif text-[1.3rem] font-light leading-tight text-ink">{project.title}</h3>
        </div>
        <p className="text-[0.84rem] leading-[1.75] text-muted font-light">{project.description}</p>
        <div className="flex flex-wrap gap-1.5 pt-1">
          {project.tags.slice(0, 3).map((tag) => <Tag key={tag} label={tag} />)}
          {project.tags.length > 3 && (
            <span className="text-[0.65rem] font-medium px-2.5 py-1 rounded-full text-muted">+{project.tags.length - 3}</span>
          )}
        </div>

        {/* "Voir plus" hint */}
        <div className="flex items-center gap-1.5 pt-2 mt-auto"
          style={{ color: "#C4748A", opacity: hovered ? 1 : 0.5, transition: "opacity 0.3s" }}>
          <span className="text-[0.72rem] font-medium tracking-[0.08em]">Voir le détail</span>
          <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2.5">
            <path d="M3 8h10M9 4l4 4-4 4"/>
          </svg>
        </div>
      </div>

      <div className="absolute bottom-0 left-0 right-0 h-[2px] rounded-full transition-all duration-500"
        style={{ background: "linear-gradient(90deg, #C4748A, #E8A0B0)", opacity: hovered ? 1 : 0 }} />
    </motion.article>
  );
}

export default function ProjectCarousel({ projects }: Props) {
  const trackRef = useRef<HTMLDivElement>(null);
  const [canScrollLeft, setCanScrollLeft] = useState(false);
  const [canScrollRight, setCanScrollRight] = useState(true);
  const [activeProject, setActiveProject] = useState<Project | null>(null);
  const sectionRef = useRef(null);
  const inView = useInView(sectionRef, { once: true, margin: "-80px" });

  const updateButtons = () => {
    const el = trackRef.current;
    if (!el) return;
    setCanScrollLeft(el.scrollLeft > 10);
    setCanScrollRight(el.scrollLeft < el.scrollWidth - el.clientWidth - 10);
  };

  useEffect(() => {
    const el = trackRef.current;
    if (!el) return;
    el.addEventListener("scroll", updateButtons);
    updateButtons();
    return () => el.removeEventListener("scroll", updateButtons);
  }, []);

  const scroll = (dir: "left" | "right") => {
    trackRef.current?.scrollBy({ left: dir === "right" ? 400 : -400, behavior: "smooth" });
  };

  return (
    <>
      <section id="projets" className="pt-24 pb-20" ref={sectionRef}
        style={{ background: "linear-gradient(180deg, #FDF6F0 0%, #FAF0F4 100%)" }}>
        <div className="px-[6vw] mb-10">
          <motion.div initial={{ opacity: 0, y: 18 }} animate={inView ? { opacity: 1, y: 0 } : {}} transition={{ duration: 0.6 }}>
            <p className="text-[0.7rem] font-medium tracking-[0.2em] uppercase text-accent mb-2 flex items-center gap-2">
              <span className="block w-6 h-px bg-accent" /> Réalisations
            </p>
            <h2 className="font-serif font-light text-[clamp(2rem,4vw,3rem)] leading-tight text-ink">Projets</h2>
            <p className="text-muted text-[0.84rem] mt-1 font-light">Clique sur un projet pour en savoir plus</p>
          </motion.div>
        </div>

        <div ref={trackRef}
          className="carousel-track flex gap-5 overflow-x-auto px-[6vw] pb-4"
          style={{ cursor: "grab" }}
          onMouseDown={(e) => {
            const el = trackRef.current;
            if (!el) return;
            const startX = e.pageX - el.offsetLeft;
            const scrollLeft = el.scrollLeft;
            const onMove = (ev: MouseEvent) => {
              el.style.cursor = "grabbing";
              el.scrollLeft = scrollLeft - (ev.pageX - el.offsetLeft - startX);
            };
            const onUp = () => {
              el.style.cursor = "grab";
              window.removeEventListener("mousemove", onMove);
              window.removeEventListener("mouseup", onUp);
            };
            window.addEventListener("mousemove", onMove);
            window.addEventListener("mouseup", onUp);
          }}
        >
          {projects.map((project, i) => (
            <ProjectCard key={project.id} project={project} index={i} onClick={() => setActiveProject(project)} />
          ))}
          <div className="flex-shrink-0 w-[2vw]" />
        </div>

        {/* Flèches en bas, centrées */}
        <div className="flex justify-center gap-4 mt-8">
          {([["left", "M10 3L5 8l5 5"], ["right", "M6 3l5 5-5 5"]] as const).map(([dir, d]) => (
            <button key={dir} onClick={() => scroll(dir)}
              disabled={dir === "left" ? !canScrollLeft : !canScrollRight}
              className="w-11 h-11 rounded-full border flex items-center justify-center transition-all duration-200 disabled:opacity-25 hover:bg-blush hover:border-accent"
              style={{ borderColor: "#EDD5DC", color: "#C4748A", background: "#fff" }}>
              <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2">
                <path d={d}/>
              </svg>
            </button>
          ))}
        </div>

      </section>

      <ProjectModal project={activeProject} onClose={() => setActiveProject(null)} />
    </>
  );
}
