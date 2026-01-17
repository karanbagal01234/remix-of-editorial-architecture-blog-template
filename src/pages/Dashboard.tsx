// FRONTEND FROZEN — BACKEND IS SOURCE OF TRUTH
import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Users, Building2, TrendingUp, Calendar, MessageCircle, Settings, LogOut, Sparkles, ArrowUpRight, Clock } from 'lucide-react';
import { useUI } from '@/context/UIContext';
import AnimatedButton from '@/components/AnimatedButton';
import AIAvatar from '@/components/AIAvatar';
import dashboardData from '@/data/dashboard.json';
import studentsData from '@/data/students.json';
import companiesData from '@/data/companies.json';

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const { logout, user } = useUI();
  const [data] = useState(dashboardData);
  const [students] = useState(studentsData);
  const [companies] = useState(companiesData);

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const statCards = [
    { icon: <TrendingUp />, label: 'Total Matches', value: data.matches, color: 'from-primary to-secondary' },
    { icon: <Clock />, label: 'Pending', value: data.pending, color: 'from-accent to-primary' },
    { icon: <Users />, label: 'Students', value: data.totalStudents, color: 'from-secondary to-accent' },
    { icon: <Building2 />, label: 'Companies', value: data.totalCompanies, color: 'from-primary to-accent' },
    { icon: <Calendar />, label: 'Interviews', value: data.interviewsScheduled, color: 'from-accent to-secondary' },
    { icon: <Sparkles />, label: 'Avg Score', value: `${data.avgScore}%`, color: 'from-secondary to-primary' },
  ];

  return (
    <div className="min-h-screen">
      <motion.aside className="fixed left-0 top-0 bottom-0 w-64 glass-strong border-r border-border z-40 hidden lg:block" initial={{ x: -100, opacity: 0 }} animate={{ x: 0, opacity: 1 }} transition={{ duration: 0.5 }}>
        <div className="p-6">
          <Link to="/" className="flex items-center gap-2 mb-8">
            <div className="w-8 h-8 rounded-lg gradient-bg flex items-center justify-center"><Sparkles className="w-5 h-5 text-primary-foreground" /></div>
            <span className="font-bold text-xl gradient-text">Aura-Match</span>
          </Link>
          <nav className="space-y-2">
            {[
              { icon: <TrendingUp />, label: 'Dashboard', path: '/dashboard', active: true },
              { icon: <MessageCircle />, label: 'Chat with Aura', path: '/chat' },
              { icon: <Settings />, label: 'Policy Simulator', path: '/policy' },
            ].map((item) => (
              <Link key={item.label} to={item.path} className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${item.active ? 'gradient-bg text-primary-foreground' : 'hover:bg-muted text-muted-foreground hover:text-foreground'}`}>
                {item.icon}<span className="font-medium">{item.label}</span>
              </Link>
            ))}
          </nav>
        </div>
        <div className="absolute bottom-6 left-6 right-6">
          <button onClick={handleLogout} className="flex items-center gap-3 px-4 py-3 w-full rounded-xl hover:bg-destructive/10 text-destructive transition-colors">
            <LogOut className="w-5 h-5" /><span className="font-medium">Logout</span>
          </button>
        </div>
      </motion.aside>

      <main className="lg:ml-64 p-6 lg:p-8">
        <motion.header className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8" initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
          <div>
            <h1 className="text-2xl md:text-3xl font-bold">Welcome back{user?.name && `, ${user.name}`}! 👋</h1>
            <p className="text-muted-foreground">Here's what's happening with your matches today.</p>
          </div>
          <Link to="/chat"><AnimatedButton size="md"><MessageCircle className="mr-2 w-5 h-5" />Chat with Aura</AnimatedButton></Link>
        </motion.header>

        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
          {statCards.map((stat, index) => (
            <motion.div key={stat.label} className="glass rounded-2xl p-4 relative overflow-hidden" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * 0.1 }} whileHover={{ y: -2 }}>
              <div className={`absolute top-0 right-0 w-20 h-20 rounded-full bg-gradient-to-br ${stat.color} opacity-20 blur-xl -translate-y-1/2 translate-x-1/2`} />
              <div className="relative">
                <div className="text-muted-foreground mb-2">{stat.icon}</div>
                <div className="text-2xl font-bold">{stat.value}</div>
                <div className="text-sm text-muted-foreground">{stat.label}</div>
              </div>
            </motion.div>
          ))}
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          <motion.div className="lg:col-span-2 glass rounded-2xl p-6" initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.3 }}>
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><Clock className="w-5 h-5 text-primary" />Recent Activity</h2>
            <div className="space-y-4">
              {data.recentActivity.map((activity: any, index: number) => (
                <motion.div key={activity.id} className="flex items-start gap-4 p-4 rounded-xl bg-muted/30 hover:bg-muted/50 transition-colors" initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.4 + index * 0.1 }}>
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${activity.type === 'match' ? 'bg-primary/20 text-primary' : activity.type === 'interview' ? 'bg-secondary/20 text-secondary' : 'bg-accent/20 text-accent'}`}>
                    {activity.type === 'match' ? <Sparkles className="w-5 h-5" /> : activity.type === 'interview' ? <Calendar className="w-5 h-5" /> : <Users className="w-5 h-5" />}
                  </div>
                  <div className="flex-1"><p className="font-medium">{activity.message}</p><p className="text-sm text-muted-foreground">{activity.time}</p></div>
                </motion.div>
              ))}
            </div>
          </motion.div>

          <motion.div className="glass rounded-2xl p-6" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.4 }}>
            <div className="flex items-center gap-3 mb-4"><AIAvatar state="idle" size="sm" /><div><h2 className="text-lg font-semibold">Aura's Insights</h2><p className="text-sm text-muted-foreground">AI-powered recommendations</p></div></div>
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-gradient-to-br from-primary/10 to-secondary/10 border border-primary/20"><p className="text-sm">"I noticed 5 students with strong React skills have applied. Would you like me to prioritize matching them?"</p></div>
              <Link to="/chat"><AnimatedButton variant="outline" className="w-full">Ask Aura<ArrowUpRight className="ml-2 w-4 h-4" /></AnimatedButton></Link>
            </div>
          </motion.div>
        </div>

        <div className="grid md:grid-cols-2 gap-6 mt-6">
          <motion.div className="glass rounded-2xl p-6" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }}>
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><Users className="w-5 h-5 text-primary" />Top Students</h2>
            <div className="space-y-3">
              {students.slice(0, 5).map((student: any) => (
                <div key={student.id} className="flex items-center gap-3 p-3 rounded-xl hover:bg-muted/30 transition-colors">
                  <div className="w-10 h-10 rounded-full bg-gradient-to-br from-primary to-secondary flex items-center justify-center text-primary-foreground font-medium">{student.name.charAt(0)}</div>
                  <div className="flex-1 min-w-0"><p className="font-medium truncate">{student.name}</p><p className="text-sm text-muted-foreground truncate">{student.course}</p></div>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${student.status === 'matched' ? 'bg-primary/20 text-primary' : student.status === 'interviewing' ? 'bg-secondary/20 text-secondary' : 'bg-muted text-muted-foreground'}`}>{student.status}</span>
                </div>
              ))}
            </div>
          </motion.div>

          <motion.div className="glass rounded-2xl p-6" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6 }}>
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><Building2 className="w-5 h-5 text-primary" />Partner Companies</h2>
            <div className="space-y-3">
              {companies.slice(0, 5).map((company: any) => (
                <div key={company.id} className="flex items-center gap-3 p-3 rounded-xl hover:bg-muted/30 transition-colors">
                  <div className="w-10 h-10 rounded-xl bg-muted flex items-center justify-center text-2xl">{company.logo}</div>
                  <div className="flex-1 min-w-0"><p className="font-medium truncate">{company.name}</p><p className="text-sm text-muted-foreground truncate">{company.industry}</p></div>
                  <span className="text-sm text-primary font-medium">{company.openings} roles</span>
                </div>
              ))}
            </div>
          </motion.div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
