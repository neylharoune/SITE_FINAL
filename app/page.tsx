import Navbar from "@/components/Navbar";
import Hero from "@/components/Hero";
import ProjectCarousel from "@/components/ProjectCarousel";
import About from "@/components/About";
import Contact from "@/components/Contact";
import Footer from "@/components/Footer";
import { projects } from "@/data/projects";

export default function Home() {
  return (
    <main>
      <Navbar />
      <Hero />
      <ProjectCarousel projects={projects} />
      <About />
      <Contact />
      <Footer />
    </main>
  );
}
