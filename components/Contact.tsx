"use client";
import { useRef } from "react";
import { motion, useInView } from "framer-motion";

export default function Contact() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-60px" });

  return (
    <section id="contact" ref={ref} className="py-24 px-[6vw]"
      style={{ background: "linear-gradient(180deg, #FAF0F4 0%, #FDF6F0 100%)", borderTop: "1px solid #EDD5DC" }}>
      <div className="max-w-2xl">
        <motion.div initial={{ opacity: 0, y: 18 }} animate={inView ? { opacity: 1, y: 0 } : {}} transition={{ duration: 0.6 }}>
          <p className="text-[0.7rem] font-medium tracking-[0.2em] uppercase text-accent mb-2 flex items-center gap-2">
            <span className="block w-6 h-px bg-accent" /> Contact
          </p>
          <h2 className="font-serif font-light text-[clamp(2rem,4vw,3rem)] leading-tight text-ink mb-4">
            Une question ?<br />Prenons contact.
          </h2>
          <p className="text-muted text-[0.92rem] leading-relaxed mb-10 font-light">
            Disponible pour des opportunités de stage, alternance ou Master.
          </p>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 16 }} animate={inView ? { opacity: 1, y: 0 } : {}} transition={{ duration: 0.6, delay: 0.2 }}
          className="flex flex-col sm:flex-row gap-4">
          <a href="mailto:neylaharoune04@gmail.com"
            className="inline-flex items-center gap-3 px-6 py-3.5 rounded-full text-[0.82rem] font-medium no-underline transition-all duration-200 hover:-translate-y-1 shadow-sm hover:shadow-md"
            style={{ background: "#C4748A", color: "#fff" }}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
              <polyline points="22,6 12,13 2,6"/>
            </svg>
            neylaharoune04@gmail.com
          </a>
          <a href="tel:0625173056"
            className="inline-flex items-center gap-3 px-6 py-3.5 rounded-full text-[0.82rem] font-medium no-underline transition-all duration-200 hover:-translate-y-1"
            style={{ background: "#fff", color: "#B08090", border: "1px solid #EDD5DC" }}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07A19.5 19.5 0 013.07 9.8a2 2 0 012-1.18h3a2 2 0 012 1.72c.127.96.361 1.903.7 2.81a2 2 0 01-.45 2.11L6.09 7.91a16 16 0 006 6l1.27-1.27a2 2 0 012.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0122 16.92z"/>
            </svg>
            06 25 17 30 56
          </a>
        </motion.div>
      </div>
    </section>
  );
}
