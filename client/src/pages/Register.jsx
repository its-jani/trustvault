import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Label } from '../components/ui/Label';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '../components/ui/Card';
import { Alert, AlertTitle, AlertDescription } from '../components/ui/Alert';
import { ShieldCheck, Lock, Mail, User, Eye, EyeOff, Check, UserCheck, ShieldAlert, Key } from 'lucide-react';

export const Register = () => {
  const { register } = useAuth();
  const navigate = useNavigate();

  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('VIEWER');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const roles = [
    {
      id: 'VIEWER',
      name: 'VIEWER',
      label: 'Authorized Consumer',
      description: 'View and download documents explicitly delegated to your email.',
      icon: UserCheck,
      color: 'border-emerald-500/80 bg-emerald-950/30 text-emerald-300'
    },
    {
      id: 'OWNER',
      name: 'OWNER',
      label: 'Vault Manager',
      description: 'Upload, envelope-encrypt, delete, and delegate document view grants.',
      icon: Key,
      color: 'border-indigo-500/80 bg-indigo-950/30 text-indigo-300'
    },
    {
      id: 'ADMIN',
      name: 'ADMIN',
      label: 'Security Officer',
      description: 'Full oversight across all documents, delegation grants, and forensic audit logs.',
      icon: ShieldAlert,
      color: 'border-violet-500/80 bg-violet-950/30 text-violet-300'
    }
  ];

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    if (!fullName.trim()) {
      setError('Please provide your full name.');
      return;
    }
    if (!email.trim()) {
      setError('Please provide a valid corporate email.');
      return;
    }
    if (password.length < 8) {
      setError('Password must contain at least 8 characters for cryptographic security.');
      return;
    }

    setIsLoading(true);
    try {
      await register({
        full_name: fullName.trim(),
        email: email.trim().toLowerCase(),
        password,
        role
      });
      navigate('/', { replace: true });
    } catch (err) {
      setError(err.message || 'Registration failed.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full bg-slate-950 flex items-center justify-center p-4 sm:p-6 lg:p-8 relative overflow-hidden">
      {/* Background radial glow */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] bg-indigo-600/10 rounded-full blur-[150px] pointer-events-none" />

      <div className="w-full max-w-xl relative z-10 my-8">
        {/* Brand Header */}
        <div className="flex flex-col items-center mb-6 text-center">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-indigo-600 to-violet-600 p-[1px] shadow-xl shadow-indigo-600/20 mb-3">
            <div className="w-full h-full bg-slate-950 rounded-[15px] flex items-center justify-center">
              <ShieldCheck className="w-8 h-8 text-indigo-400" />
            </div>
          </div>
          <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
            Create an Identity in <span className="text-indigo-400">TrustVault</span>
          </h1>
          <p className="text-xs uppercase tracking-widest text-slate-400 font-semibold mt-1">
            Zero-Trust Access Control & Delegation
          </p>
        </div>

        {/* Register Card */}
        <Card className="border-slate-800/90 bg-slate-900/80 backdrop-blur-2xl">
          <CardHeader>
            <CardTitle className="text-xl">Account Credentials</CardTitle>
            <CardDescription>
              Register your identity. All data is protected by AES-256-GCM and live PEP authorization.
            </CardDescription>
          </CardHeader>

          <CardContent>
            {error && (
              <div className="mb-5">
                <Alert variant="destructive">
                  <AlertTitle>Registration Error</AlertTitle>
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <Label htmlFor="fullName">Full Legal Name</Label>
                <div className="relative">
                  <Input
                    id="fullName"
                    type="text"
                    autoComplete="name"
                    placeholder="Jane Doe"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    className="pl-10"
                    disabled={isLoading}
                    required
                  />
                  <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5 pointer-events-none" />
                </div>
              </div>

              <div>
                <Label htmlFor="email">Email Address</Label>
                <div className="relative">
                  <Input
                    id="email"
                    type="email"
                    autoComplete="email"
                    placeholder="jane.doe@organization.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="pl-10"
                    disabled={isLoading}
                    required
                  />
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5 pointer-events-none" />
                </div>
              </div>

              <div>
                <Label htmlFor="password">Master Password (Min 8 Characters)</Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="new-password"
                    placeholder="••••••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="pl-10 pr-10"
                    disabled={isLoading}
                    required
                  />
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5 pointer-events-none" />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3.5 top-3 text-slate-500 hover:text-slate-300 transition-colors"
                    tabIndex={-1}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Role Selection */}
              <div className="pt-2">
                <Label>Select Initial Security Role</Label>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-1.5">
                  {roles.map((r) => {
                    const isSelected = role === r.id;
                    const IconComponent = r.icon;
                    return (
                      <div
                        key={r.id}
                        onClick={() => setRole(r.id)}
                        className={`cursor-pointer rounded-xl border p-3.5 flex flex-col justify-between transition-all duration-200 select-none ${
                          isSelected
                            ? `${r.color} shadow-lg ring-1 ring-indigo-500/40`
                            : 'border-slate-800 bg-slate-900/50 hover:bg-slate-800/40 text-slate-400'
                        }`}
                      >
                        <div>
                          <div className="flex items-center justify-between mb-2">
                            <span className="p-1.5 rounded-lg bg-slate-800/80 text-white">
                              <IconComponent className="w-4 h-4" />
                            </span>
                            {isSelected && (
                              <span className="w-5 h-5 rounded-full bg-indigo-500 text-white flex items-center justify-center">
                                <Check className="w-3 h-3 stroke-[3]" />
                              </span>
                            )}
                          </div>
                          <h4 className="text-sm font-bold text-white tracking-tight">{r.name}</h4>
                          <p className="text-[11px] font-medium text-slate-300 mb-1">{r.label}</p>
                        </div>
                        <p className="text-[10px] text-slate-400 leading-snug mt-2 pt-2 border-t border-slate-800/60">
                          {r.description}
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>

              <Button
                type="submit"
                className="w-full mt-4"
                isLoading={isLoading}
              >
                Provision TrustVault Account
              </Button>
            </form>
          </CardContent>

          <CardFooter className="flex flex-col space-y-3 border-t border-slate-800/60 pt-4">
            <div className="text-center text-xs text-slate-400">
              Already possess credentials?{' '}
              <Link to="/login" className="text-indigo-400 hover:text-indigo-300 font-semibold underline underline-offset-4">
                Sign in to vault
              </Link>
            </div>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
};

export default Register;
