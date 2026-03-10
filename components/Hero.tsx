"use client";
import { motion } from "framer-motion";
import Image from "next/image";

const fadeUp = (delay: number) => ({
  initial: { opacity: 0, y: 24 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.8, delay, ease: [0.22, 1, 0.36, 1] },
});

export default function Hero() {
  return (
    <section className="min-h-screen grid md:grid-cols-2 items-center px-[6vw] pt-24 pb-16 gap-[5vw] relative overflow-hidden">
      {/* background blobs */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute -top-32 -right-32 w-[600px] h-[600px] rounded-full opacity-40"
          style={{ background: "radial-gradient(circle, #F5DCE4 0%, transparent 65%)" }} />
        <div className="absolute bottom-0 -left-32 w-[400px] h-[400px] rounded-full opacity-30"
          style={{ background: "radial-gradient(circle, #EDD5DC 0%, transparent 65%)" }} />
        {/* subtle floral pattern overlay */}
        <svg className="absolute inset-0 w-full h-full opacity-[0.03]" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <pattern id="floral" x="0" y="0" width="60" height="60" patternUnits="userSpaceOnUse">
              <circle cx="30" cy="30" r="2" fill="#C4748A"/>
              <circle cx="10" cy="10" r="1" fill="#C4748A"/>
              <circle cx="50" cy="10" r="1" fill="#C4748A"/>
              <circle cx="10" cy="50" r="1" fill="#C4748A"/>
              <circle cx="50" cy="50" r="1" fill="#C4748A"/>
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#floral)"/>
        </svg>
      </div>

      {/* Text */}
      <div className="relative z-10">
        <motion.span {...fadeUp(0.1)}
          className="inline-flex items-center gap-2 text-[0.7rem] font-medium tracking-[0.2em] uppercase text-accent mb-7">
          <span className="block w-8 h-px bg-accent" />
          Portfolio
        </motion.span>

        <motion.h1 {...fadeUp(0.22)}
          className="font-serif font-light text-[clamp(3rem,6vw,4.8rem)] leading-[1.06] tracking-tight mb-5 text-ink">
          Étudiante en<br />
          <em className="italic text-accent">L3 Informatique</em><br />
          à Rennes.
        </motion.h1>

        <motion.p {...fadeUp(0.36)}
          className="text-muted text-[1rem] leading-[1.88] max-w-[460px] mb-9 font-light">
          Je conçois des circuits numériques, développe des applications web et explore les systèmes bas niveau. Candidate en Master Informatique.
        </motion.p>

        <motion.div {...fadeUp(0.5)} className="flex items-center gap-5 flex-wrap">
          <a href="#projets"
            className="inline-flex items-center gap-2 bg-accent text-white text-[0.78rem] font-medium tracking-[0.1em] uppercase px-7 py-3 rounded-full hover:bg-accent2 hover:-translate-y-0.5 transition-all duration-200 no-underline shadow-sm">
            Voir mes projets
            <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M8 3v10M3 8l5 5 5-5"/>
            </svg>
          </a>
          <a href="#contact"
            className="text-[0.76rem] font-medium tracking-[0.1em] uppercase text-muted hover:text-accent transition-all no-underline border-b border-border hover:border-accent pb-0.5">
            Me contacter
          </a>
        </motion.div>

        <motion.div {...fadeUp(0.62)} className="flex gap-8 mt-12">
          {[
            { n: "4", label: "Projets" },
            { n: "3", label: "Universités" },
            { n: "B2", label: "Anglais" },
          ].map(({ n, label }) => (
            <div key={label} className="text-center">
              <div className="font-serif text-2xl text-accent font-light leading-none">{n}</div>
              <div className="text-[0.65rem] text-muted tracking-[0.14em] uppercase mt-1">{label}</div>
            </div>
          ))}
        </motion.div>
      </div>

      {/* Photo */}
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 1, delay: 0.3, ease: [0.22, 1, 0.36, 1] }}
        className="relative z-10 flex justify-center md:justify-end"
      >
        <div className="relative w-[clamp(220px,26vw,320px)] h-[clamp(270px,32vw,400px)]">
          {/* blush ring behind photo */}
          <div className="absolute inset-[-14px] rounded-full border border-accent/20" />
          <div className="absolute inset-[-28px] rounded-full border border-accent/10" />
          <Image
            src="/images/neyla.png"
            alt="Neyla Haroune"
            fill
            className="object-cover object-center rounded-full shadow-lg"
            style={{ filter: "brightness(1.02) contrast(1.02)", objectPosition: "center 10%" }}
            priority
          />
        </div>
      </motion.div>
    </section>
  );
}
