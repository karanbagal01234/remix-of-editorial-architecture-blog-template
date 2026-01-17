/**
 * Aura-Match Application
 * 
 * Production-ready internship matching platform
 */
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { UIProvider } from "@/context/UIContext";
import { CompanyProvider } from "@/context/CompanyContext";
import FlowGuard from "@/components/FlowGuard";
import CompanyFlowGuard from "@/components/CompanyFlowGuard";

// Pages
import Landing from "./pages/Landing";
import Login from "./pages/Login";
import AuthCallback from "./pages/AuthCallback";
import Onboard from "./pages/Onboard";
import VerifyEmail from "./pages/VerifyEmail";
import VerifyPhone from "./pages/VerifyPhone";
import Dashboard from "./pages/Dashboard";
import Chat from "./pages/Chat";
import PolicySimulator from "./pages/PolicySimulator";

// Student Pages
import StudentProfile from "./pages/student/Profile";
import StudentDashboard from "./pages/student/Dashboard";
import SkillExtraction from "./pages/student/SkillExtraction";
import Preferences from "./pages/student/Preferences";
import Status from "./pages/student/Status";
import Result from "./pages/student/Result";
import History from "./pages/student/History";
import Notifications from "./pages/student/Notifications";
import Offers from "./pages/student/Offers";

// Company Pages
import CompanyLogin from "./pages/company/Login";
import CompanyVerifyEmail from "./pages/company/VerifyEmail";
import CompanyProfile from "./pages/company/Profile";
import CreateJob from "./pages/company/CreateJob";
import JobStatus from "./pages/company/JobStatus";
import JobMatches from "./pages/company/JobMatches";

import NotFound from "./pages/NotFound";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      retry: 1,
    },
  },
});

const App = () => (
  <QueryClientProvider client={queryClient}>
    <UIProvider>
      <CompanyProvider>
        <TooltipProvider>
          <Toaster />
          <Sonner />
          <BrowserRouter>
            <Routes>
              {/* Public Routes */}
              <Route path="/" element={<Landing />} />
              <Route path="/onboard" element={<Onboard />} />
              <Route path="/login" element={<Login />} />
              <Route path="/auth/callback" element={<AuthCallback />} />
              <Route path="/verify/email" element={<VerifyEmail />} />
              <Route path="/verify/phone" element={<VerifyPhone />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/chat" element={<Chat />} />
              <Route path="/policy" element={<PolicySimulator />} />
              
              {/* Protected Student Routes with Flow Enforcement */}
              <Route path="/student/dashboard" element={
                <FlowGuard step="status">
                  <StudentDashboard />
                </FlowGuard>
              } />
              <Route path="/student/profile" element={
                <FlowGuard step="profile">
                  <StudentProfile />
                </FlowGuard>
              } />
              <Route path="/student/skill-extraction" element={
                <FlowGuard step="skills">
                  <SkillExtraction />
                </FlowGuard>
              } />
              <Route path="/student/preferences" element={
                <FlowGuard step="preferences">
                  <Preferences />
                </FlowGuard>
              } />
              <Route path="/student/status" element={
                <FlowGuard step="status">
                  <Status />
                </FlowGuard>
              } />
              <Route path="/student/result" element={
                <FlowGuard step="result">
                  <Result />
                </FlowGuard>
              } />
              <Route path="/student/offers" element={
                <FlowGuard step="status">
                  <Offers />
                </FlowGuard>
              } />
              <Route path="/student/notifications" element={
                <FlowGuard step="status">
                  <Notifications />
                </FlowGuard>
              } />
              <Route path="/student/history" element={
                <FlowGuard step="status">
                  <History />
                </FlowGuard>
              } />

              {/* Company Routes */}
              <Route path="/company/login" element={<CompanyLogin />} />
              <Route path="/company/verify-email" element={
                <CompanyFlowGuard step="verify">
                  <CompanyVerifyEmail />
                </CompanyFlowGuard>
              } />
              <Route path="/company/profile" element={
                <CompanyFlowGuard step="profile">
                  <CompanyProfile />
                </CompanyFlowGuard>
              } />
              <Route path="/company/jobs/create" element={
                <CompanyFlowGuard step="create-job">
                  <CreateJob />
                </CompanyFlowGuard>
              } />
              <Route path="/company/jobs/status" element={
                <CompanyFlowGuard step="job-status">
                  <JobStatus />
                </CompanyFlowGuard>
              } />
              <Route path="/company/jobs/matches/:jobId" element={
                <CompanyFlowGuard step="job-matches">
                  <JobMatches />
                </CompanyFlowGuard>
              } />
              
              {/* 404 */}
              <Route path="*" element={<NotFound />} />
            </Routes>
          </BrowserRouter>
        </TooltipProvider>
      </CompanyProvider>
    </UIProvider>
  </QueryClientProvider>
);

export default App;
