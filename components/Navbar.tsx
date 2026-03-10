"use client";
import { useState, useEffect } from "react";
import Link from "next/link";

const links = [
  { href: "#projets", label: "Projets" },
  { href: "#about", label: "À propos" },
  { href: "#contact", label: "Contact" },
];

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 40);
    window.addEventListener("scroll", onScroll);
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <nav className={`fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-[6vw] h-16 transition-all duration-300 ${
      scrolled ? "bg-bg/90 backdrop-blur-xl border-b border-border shadow-sm" : "bg-transparent"
    }`}>
      <Link href="#" className="font-serif text-xl text-ink no-underline tracking-wide font-light">
        Neyla<span className="text-accent italic">.</span>
      </Link>
      <ul className="hidden md:flex gap-8 list-none">
        {links.map(({ href, label }) => (
          <li key={href}>
            <a href={href} className="text-[0.72rem] font-medium tracking-[0.14em] uppercase text-muted hover:text-accent transition-colors no-underline">
              {label}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  );
}
