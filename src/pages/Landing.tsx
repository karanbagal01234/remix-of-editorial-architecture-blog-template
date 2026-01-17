/**
 * Landing Page - Aura-Match
 */
import React, { useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import gsap from 'gsap';
import AIAvatar from '@/components/AIAvatar';
import AnimatedButton from '@/components/AnimatedButton';
import { Sparkles, Users, Building2, ArrowRight, CheckCircle } from 'lucide-react';

const Landing: React.FC = () => {
  const heroRef = useRef<HTMLDivElement>(null);
  const titleRef = useRef<HTMLHeadingElement>(null);
  const subtitleRef = useRef<HTMLParagraphElement>(null);
  const cardsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const ctx = gsap.context(() => {
      // Hero timeline animation
      const tl = gsap.timeline({ defaults: { ease: 'power3.out' } });

      tl.from(titleRef.current, {
        y: 100,
        opacity: 0,
        duration: 1,
        skewY: 5,
      })
        .from(
          subtitleRef.current,
          {
            y: 50,
            opacity: 0,
            duration: 0.8,
          },
          '-=0.5'
        )
        .from(
          '.hero-buttons',
          {
            y: 30,
            opacity: 0,
            duration: 0.6,
          },
          '-=0.3'
        );

      // Parallax effect on scroll
      gsap.to('.hero-bg-shape', {
        yPercent: -30,
        ease: 'none',
        scrollTrigger: {
          trigger: heroRef.current,
          start: 'top top',
          end: 'bottom top',
          scrub: true,
        },
      });

      // Cards stagger animation
      gsap.from('.feature-card', {
        scrollTrigger: {
          trigger: cardsRef.current,
          start: 'top 80%',
        },
        y: 60,
        opacity: 0,
        duration: 0.8,
        stagger: 0.15,
      });
    });

    return () => ctx.revert();
  }, []);

  const features = [
    {
      icon: <Sparkles className="w-6 h-6" />,
      title: 'AI-Powered Matching',
      description: 'Smart algorithms that understand skills, culture, and aspirations to find perfect fits.',
    },
    {
      icon: <Users className="w-6 h-6" />,
      title: 'Student-Centric',
      description: 'Personalized journey from profile creation to landing your dream opportunity.',
    },
    {
      icon: <Building2 className="w-6 h-6" />,
      title: 'Industry Partners',
      description: 'Connected with 89+ leading companies actively seeking fresh talent.',
    },
    {
      icon: <CheckCircle className="w-6 h-6" />,
      title: 'Verified Credentials',
      description: 'Email and phone OTP verification ensures authentic and trusted user identity.',
    },
  ];

  return (
    <div className="min-h-screen overflow-hidden">
      {/* Navigation */}
      <motion.nav
        className="fixed top-0 left-0 right-0 z-50 glass"
        initial={{ y: -100 }}
        animate={{ y: 0 }}
        transition={{ duration: 0.6, delay: 0.2 }}
      >
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg gradient-bg flex items-center justify-center">
              <Sparkles className="w-5 h-5 text-primary-foreground" />
            </div>
            <span className="font-bold text-xl gradient-text">Aura-Match</span>
          </Link>
          <div className="flex items-center gap-6">
            {/* Portal Links */}
            <div className="hidden sm:flex items-center gap-4 text-sm">
              <Link 
                to="/login" 
                className="text-muted-foreground hover:text-foreground transition-colors"
              >
                Student Portal
              </Link>
              <span className="text-border">|</span>
              <Link 
                to="/company/login" 
                className="text-muted-foreground hover:text-foreground transition-colors"
              >
                Company Portal
              </Link>
            </div>
            
            <Link to="/onboard">
              <AnimatedButton size="sm">Get Started</AnimatedButton>
            </Link>
          </div>
        </div>
      </motion.nav>

      {/* Hero Section */}
      <section ref={heroRef} className="relative min-h-screen flex items-center justify-center pt-20">
        {/* Background shapes */}
        <div className="absolute inset-0 overflow-hidden">
          <div className="hero-bg-shape absolute top-20 -left-20 w-96 h-96 rounded-full bg-gradient-to-br from-primary/20 to-secondary/20 blur-3xl" />
          <div className="hero-bg-shape absolute bottom-20 -right-20 w-80 h-80 rounded-full bg-gradient-to-br from-accent/20 to-primary/20 blur-3xl" />
          <div className="hero-bg-shape absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full bg-gradient-to-br from-secondary/10 to-accent/10 blur-3xl" />
        </div>

        <div className="relative container mx-auto px-6 text-center">
          {/* Floating Avatar */}
          <motion.div
            className="flex justify-center mb-8"
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.3, type: 'spring', stiffness: 200 }}
          >
            <AIAvatar state="idle" size="xl" />
          </motion.div>

          <h1
            ref={titleRef}
            className="text-5xl md:text-7xl font-bold mb-6 leading-tight"
          >
            Meet <span className="gradient-text">Aura</span>
            <br />
            Your AI Matching Assistant
          </h1>

          <p
            ref={subtitleRef}
            className="text-xl md:text-2xl text-muted-foreground max-w-2xl mx-auto mb-10"
          >
            Connecting talented students with their dream opportunities through
            intelligent, personalized matching.
          </p>

          <div className="hero-buttons flex flex-col sm:flex-row gap-4 justify-center">
            <Link to="/login">
              <AnimatedButton size="lg" className="w-full sm:w-auto">
                Start Your Journey
                <ArrowRight className="inline-block ml-2 w-5 h-5" />
              </AnimatedButton>
            </Link>
            <Link to="/chat">
              <AnimatedButton variant="outline" size="lg" className="w-full sm:w-auto">
                Chat with Aura
              </AnimatedButton>
            </Link>
          </div>

          {/* Stats */}
          <motion.div
            className="mt-16 flex flex-wrap justify-center gap-8 md:gap-16"
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 1, duration: 0.6 }}
          >
            {[
              { value: '1,247+', label: 'Students' },
              { value: '89+', label: 'Companies' },
              { value: '378', label: 'Matches Made' },
            ].map((stat) => (
              <div key={stat.label} className="text-center">
                <div className="text-3xl md:text-4xl font-bold gradient-text">{stat.value}</div>
                <div className="text-muted-foreground">{stat.label}</div>
              </div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 relative">
        <div className="container mx-auto px-6">
          <motion.div
            className="text-center mb-16"
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
          >
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Why Choose <span className="gradient-text">Aura-Match</span>?
            </h2>
            <p className="text-muted-foreground text-lg max-w-xl mx-auto">
              A smarter way to connect talent with opportunity
            </p>
          </motion.div>

          <div ref={cardsRef} className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {features.map((feature) => (
              <motion.div
                key={feature.title}
                className="feature-card glass rounded-2xl p-6 hover:shadow-xl transition-shadow"
                whileHover={{ y: -5 }}
              >
                <div className="w-12 h-12 rounded-xl gradient-bg flex items-center justify-center mb-4 text-primary-foreground">
                  {feature.icon}
                </div>
                <h3 className="text-lg font-semibold mb-2">{feature.title}</h3>
                <p className="text-muted-foreground text-sm">{feature.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20">
        <div className="container mx-auto px-6">
          <motion.div
            className="glass-strong rounded-3xl p-10 md:p-16 text-center relative overflow-hidden"
            initial={{ opacity: 0, scale: 0.95 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
          >
            <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-accent/5" />
            <div className="relative">
              <h2 className="text-3xl md:text-4xl font-bold mb-4">
                Ready to Find Your Perfect Match?
              </h2>
              <p className="text-muted-foreground text-lg mb-8 max-w-xl mx-auto">
                Join thousands of students who have already found their dream opportunities with Aura.
              </p>
              <Link to="/login">
                <AnimatedButton size="lg">
                  Get Started Now
                  <ArrowRight className="inline-block ml-2 w-5 h-5" />
                </AnimatedButton>
              </Link>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 border-t border-border">
        <div className="container mx-auto px-6 text-center text-muted-foreground">
          <p>© 2026 Aura-Match. Connecting talent with opportunity.</p>
        </div>
      </footer>
    </div>
  );
};

export default Landing;
