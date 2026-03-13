"use client";
import { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import Image from "next/image";
import type { Project } from "@/types";

interface Props {
  project: Project | null;
  onClose: () => void;
}

export default function ProjectModal({ project, onClose }: Props) {
  // close on Escape
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // lock scroll
  useEffect(() => {
    if (project) document.body.style.overflow = "hidden";
    else document.body.style.overflow = "";
    return () => { document.body.style.overflow = ""; };
  }, [project]);

  return (
    <AnimatePresence>
      {project && (
        <>
          {/* Backdrop */}
          <motion.div
            key="backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.25 }}
            onClick={onClose}
            className="fixed inset-0 z-50"
            style={{ background: "rgba(61,32,48,0.45)", backdropFilter: "blur(6px)" }}
          />

          {/* Modal */}
          <motion.div
            key="modal"
            initial={{ opacity: 0, y: 40, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 30, scale: 0.97 }}
            transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
            className="fixed inset-0 z-50 flex items-center justify-center px-4 py-8 pointer-events-none"
          >
            <div
              className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-2xl pointer-events-auto"
              style={{ background: "#FFFFFF", border: "1px solid #EDD5DC", boxShadow: "0 32px 80px rgba(61,32,48,0.18)" }}
              onClick={(e) => e.stopPropagation()}
            >
              {/* Image header */}
              <div className="relative w-full h-52 overflow-hidden rounded-t-2xl"
                style={{ background: "#FAF0F4" }}>
                <Image
                  src={project.image}
                  alt={project.title}
                  fill
                  className="object-cover"
                  style={{ filter: "brightness(0.9)" }}
                />
                <div className="absolute inset-0"
                  style={{ background: "linear-gradient(to bottom, transparent 40%, rgba(255,255,255,0.95) 100%)" }} />

                {/* Close button */}
                <button onClick={onClose}
                  className="absolute top-4 right-4 w-9 h-9 rounded-full flex items-center justify-center transition-all hover:scale-110"
                  style={{ background: "rgba(255,255,255,0.9)", border: "1px solid #EDD5DC", color: "#B08090" }}>
                  <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <path d="M2 2l12 12M14 2L2 14"/>
                  </svg>
                </button>

                {/* badges */}
                <div className="absolute top-4 left-4 flex gap-2">
                  <span className="text-[0.62rem] font-semibold tracking-[0.1em] uppercase px-3 py-1 rounded-full"
                    style={{
                      background: project.type === "personnel" ? "#C4748A" : "rgba(255,255,255,0.9)",
                      color: project.type === "personnel" ? "#fff" : "#B08090",
                      border: project.type !== "personnel" ? "1px solid #EDD5DC" : "none",
                    }}>
                    {project.type === "personnel" ? "✦ Perso" : "Académique"}
                  </span>
                  <span className="text-[0.62rem] font-medium tracking-wider px-3 py-1 rounded-full"
                    style={{ background: "rgba(255,255,255,0.9)", color: "#B08090", border: "1px solid #EDD5DC" }}>
                    {project.year}
                  </span>
                </div>
              </div>

              {/* Content */}
              <div className="p-7">
                <p className="text-[0.68rem] font-medium tracking-[0.14em] uppercase text-accent mb-1">
                  {project.subtitle}
                </p>
                <h2 className="font-serif font-light text-[1.8rem] leading-tight text-ink mb-3">
                  {project.title}
                </h2>
                <p className="text-muted text-[0.9rem] leading-[1.8] font-light mb-6">
                  {project.longDescription}
                </p>

                {/* Details list */}
                <div className="mb-6">
                  <p className="text-[0.68rem] font-medium tracking-[0.14em] uppercase text-muted mb-3">
                    Détails du projet
                  </p>
                  <ul className="space-y-2.5">
                    {project.modal.details.map((detail, i) => (
                      <li key={i} className="flex gap-3 items-start text-[0.87rem] text-muted font-light leading-[1.7]">
                        <span className="mt-1.5 w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: "#EDD5DC" }} />
                        {detail}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Tags */}
                <div className="flex flex-wrap gap-1.5 mb-7">
                  {project.tags.map((tag) => (
                    <span key={tag} className="text-[0.65rem] font-medium tracking-[0.05em] px-2.5 py-1 rounded-full"
                      style={{ background: "#FAF0F4", color: "#B08090", border: "1px solid #EDD5DC" }}>
                      {tag}
                    </span>
                  ))}
                </div>

                {/* Actions */}
                <div className="flex gap-3 flex-wrap pt-5" style={{ borderTop: "1px solid #EDD5DC" }}>
                  <a
                    href={project.modal.downloadHref}
                    download
                    className="inline-flex items-center gap-2.5 px-6 py-3 rounded-full text-[0.8rem] font-medium no-underline transition-all hover:-translate-y-0.5 hover:shadow-md"
                    style={{ background: "#C4748A", color: "#fff" }}
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                      <polyline points="7 10 12 15 17 10"/>
                      <line x1="12" y1="15" x2="12" y2="3"/>
                    </svg>
                    {project.modal.downloadLabel}
                  </a>
                  {project.modal.externalLink && (
                    <a
                      href={project.modal.externalLink}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-2.5 px-6 py-3 rounded-full text-[0.8rem] font-medium no-underline transition-all hover:-translate-y-0.5"
                      style={{ background: "#FAF0F4", color: "#B08090", border: "1px solid #EDD5DC" }}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                        <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/>
                        <polyline points="15 3 21 3 21 9"/>
                        <line x1="10" y1="14" x2="21" y2="3"/>
                      </svg>
                      {project.modal.externalLabel}
                    </a>
                  )}
                  <button onClick={onClose}
                    className="inline-flex items-center gap-2 px-5 py-3 rounded-full text-[0.78rem] font-medium transition-all hover:text-ink"
                    style={{ color: "#B08090" }}>
                    Fermer
                  </button>
                </div>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
