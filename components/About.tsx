"use client";
import { useRef } from "react";
import { motion, useInView } from "framer-motion";

const skills = [
  { category: "Langages", items: ["Python", "Java", "C", "C++", "WhyML", "TypeScript", "Assembleur RISC-V", "SQL"] },
  { category: "Web", items: ["HTML", "CSS", "PHP", "JavaScript", "Flask"] },
  { category: "Théorie", items: ["Théorie des Graphes", "Langages formels", "Compilation", "Logique", "Algorithmique"] },
  { category: "Systèmes & Réseaux", items: ["Linux/Unix", "Bash", "TCP/UDP/IP", "DNS", "Modèle OSI"] },
  { category: "Outils", items: ["Git", "Wireshark", "Logisim", "LaTeX", "MySQL", "PostgreSQL", "VS Code", "PlantUML"] },
];

export default function About() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });

  return (
    <section id="about" ref={ref} className="py-24 px-[6vw] bg-surface">
      <motion.div initial={{ opacity: 0, y: 18 }} animate={inView ? { opacity: 1, y: 0 } : {}} transition={{ duration: 0.6 }} className="mb-12">
        <p className="text-[0.7rem] font-medium tracking-[0.2em] uppercase text-accent mb-2 flex items-center gap-2">
          <span className="block w-6 h-px bg-accent" /> Qui suis-je
        </p>
        <h2 className="font-serif font-light text-[clamp(2rem,4vw,3rem)] leading-tight text-ink">
          À propos
        </h2>
      </motion.div>

      <div className="grid md:grid-cols-2 gap-16 items-start">
        <motion.div initial={{ opacity: 0, x: -20 }} animate={inView ? { opacity: 1, x: 0 } : {}} transition={{ duration: 0.7, delay: 0.15 }}>
          <div className="space-y-4 text-[0.97rem] leading-[1.92] font-light" style={{ color: "#6B3A52" }}>
            <p>De <span className="font-medium" style={{ color: "#3D2030" }}>Tizi Ouzou</span> à <span className="font-medium" style={{ color: "#3D2030" }}>Angers</span> puis <span className="font-medium" style={{ color: "#3D2030" }}>Rennes</span>, mon parcours m&apos;a appris à toujours chercher le lien entre les concepts et leur mise en œuvre, de la logique formelle aux systèmes bas niveau, en passant par l&apos;algorithmique et les réseaux.</p>
            <p>Trilingue (français, anglais B2, kabyle/arabe), j&apos;aborde chaque problème avec rigueur et curiosité.</p>
          </div>

          <div className="mt-10 space-y-5">
            {[
              { year: "2025–Présent", school: "Université de Rennes", degree: "L3 Informatique" },
              { year: "2023–2025", school: "Université d'Angers", degree: "L1 & L2 Informatique" },
              { year: "2022–2023", school: "Université de Tizi Ouzou", degree: "L1 Informatique" },
            ].map(({ year, school, degree }) => (
              <div key={year} className="flex gap-5 items-start">
                <div className="text-[0.68rem] tracking-wider whitespace-nowrap pt-0.5 w-28 shrink-0" style={{ color: "#7A4060" }}>{year}</div>
                <div className="border-l-2 pl-5" style={{ borderColor: "#C4748A" }}>
                  <div className="text-[0.9rem] font-medium text-ink">{degree}</div>
                  <div className="text-[0.78rem] mt-0.5" style={{ color: "#7A4060" }}>{school}</div>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, x: 20 }} animate={inView ? { opacity: 1, x: 0 } : {}} transition={{ duration: 0.7, delay: 0.25 }} className="space-y-6">
          {skills.map(({ category, items }) => (
            <div key={category}>
              <p className="text-[0.67rem] font-medium tracking-[0.15em] uppercase mb-3" style={{ color: "#7A4060" }}>{category}</p>
              <div className="flex flex-wrap gap-2">
                {items.map((item) => (
                  <span key={item}
                    className="text-[0.76rem] px-3 py-1.5 rounded-full transition-all duration-200 hover:border-accent/60 hover:text-accent cursor-default font-light"
                    style={{ background: "#FAF0F4", border: "1px solid #C4748A", color: "#6B3A52" }}>
                    {item}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
