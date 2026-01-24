
import React from 'react';

interface SidebarProps {
  isOpen: boolean;
  onClose: () => void;
}

const UPTM_LINKS = [
  {
    name: 'Student Portal',
    url: 'https://www.uptm.edu.my/index.php/students/student-portal',
    description: 'Access student services and information',
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
      </svg>
    ),
    category: 'Academic'
  },
  {
    name: 'MyCMS Portal',
    url: 'https://mycms.kptm.edu.my:8000/login',
    description: 'Course management system',
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
      </svg>
    ),
    category: 'Academic'
  },
  {
    name: 'Learning Portal (LMS)',
    url: 'https://lms.uptm.edu.my/1225/login/index.php',
    description: 'Online learning management system',
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
      </svg>
    ),
    category: 'Learning'
  },
  {
    name: 'Timetable',
    url: 'https://uptm.edupage.org/timetable/',
    description: 'View your class schedule',
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
      </svg>
    ),
    category: 'Academic'
  },
  {
    name: 'E-Payment',
    url: 'https://epay.kptm.edu.my/',
    description: 'Online payment platform',
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a2 2 0 002-2V5a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
      </svg>
    ),
    category: 'Finance'
  },
  {
    name: 'Academic Calendar',
    url: 'https://www.uptm.edu.my/index.php/students/academic-calendar',
    description: 'Important dates and deadlines',
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
      </svg>
    ),
    category: 'Academic'
  },
];

const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose }) => {
  const categories = ['Academic', 'Learning', 'Finance'];

  return (
    <>
      {/* Overlay */}
      <div
        className={`fixed inset-0 bg-black/60 backdrop-blur-sm z-[70] transition-opacity duration-300 ${isOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'}`}
        onClick={onClose}
      />

      {/* Sidebar Panel */}
      <aside
        className={`fixed left-0 top-0 h-full w-80 bg-gradient-to-b from-gray-900 via-gray-900 to-gray-800 border-r border-gray-700 z-[80] shadow-2xl transition-transform duration-300 ease-out transform ${isOpen ? 'translate-x-0' : '-translate-x-full'}`}
      >
        <div className="flex flex-col h-full">
          {/* Header */}
          <div className="p-6 border-b border-gray-700/50 flex justify-between items-center bg-gradient-to-r from-cyan-600/10 to-blue-600/10">
            <div>
              <h2 className="text-2xl font-black text-white bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
                UPTM
              </h2>
              <p className="text-xs text-cyan-400 font-bold tracking-widest uppercase">Student Portal</p>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-gray-800/80 rounded-xl text-gray-400 hover:text-white transition-all duration-200 hover:scale-105"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          {/* Navigation */}
          <nav className="flex-1 overflow-y-auto p-4 space-y-6 custom-scrollbar">
            {categories.map((category) => {
              const categoryLinks = UPTM_LINKS.filter(link => link.category === category);
              return (
                <div key={category} className="space-y-3">
                  <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider px-2 border-l-2 border-cyan-500 pl-3">
                    {category}
                  </h3>
                  <div className="space-y-2">
                    {categoryLinks.map((link) => (
                      <a
                        key={link.name}
                        href={link.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="group flex items-center gap-4 p-4 rounded-xl text-gray-400 hover:text-white hover:bg-gradient-to-r hover:from-gray-800/80 hover:to-gray-700/80 border border-transparent hover:border-gray-600/50 transition-all duration-200 hover:scale-[1.02] hover:shadow-lg"
                        title={link.description}
                      >
                        <div className="p-2.5 rounded-lg bg-gradient-to-br from-gray-800 to-gray-700 text-cyan-500 group-hover:from-cyan-500/20 group-hover:to-blue-500/20 group-hover:text-cyan-400 transition-all duration-200 group-hover:scale-110">
                          {link.icon}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="font-semibold text-sm truncate">{link.name}</div>
                          <div className="text-xs text-gray-500 group-hover:text-gray-400 truncate">{link.description}</div>
                        </div>
                        <svg className="w-4 h-4 opacity-0 group-hover:opacity-100 transition-all duration-200 transform group-hover:translate-x-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                        </svg>
                      </a>
                    ))}
                  </div>
                </div>
              );
            })}
          </nav>

          {/* Footer */}
          <div className="p-6 border-t border-gray-700/50 bg-gradient-to-r from-gray-800/50 to-gray-900/50">
            <div className="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 rounded-2xl p-4 border border-cyan-500/20">
              <div className="flex items-center gap-3 mb-2">
                <div className="w-8 h-8 rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 flex items-center justify-center">
                  <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <div>
                  <p className="text-xs text-cyan-400 font-black uppercase tracking-tighter">UPTM Campus Shield</p>
                  <p className="text-[10px] text-gray-500">Secure • Fast • Reliable</p>
                </div>
              </div>
              <p className="text-[10px] text-gray-400 text-RIGHT leading-relaxed">
               Where Knowledge Meets Innovation Creating Opportunities, Building Futures
              </p>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
};

export default Sidebar;
