/* ============================================
   GUARDIANHEALTH — MOCK DATA
   ============================================ */
window.MOCK_USERS = [
  { id: 'u1', name: 'Dr. Sarah Admin', email: 'admin@guardian.health', role: 'admin', status: 'active', mfaEnabled: true, lastLogin: 'Oct 24, 2023 8:12 AM', department: 'IT Security' },
  { id: 'u2', name: 'Dr. James Wilson', email: 'doctor@guardian.health', role: 'doctor', status: 'active', mfaEnabled: true, lastLogin: 'Oct 24, 2023 9:30 AM', department: 'Cardiology' },
  { id: 'u3', name: 'Emily Chen', email: 'patient@guardian.health', role: 'patient', status: 'active', mfaEnabled: true, lastLogin: 'Oct 23, 2023 2:45 PM', department: null },
  { id: 'u4', name: 'Marcus Johnson', email: 'staff@guardian.health', role: 'staff', status: 'active', mfaEnabled: false, lastLogin: 'Oct 24, 2023 7:55 AM', department: 'Triage' },
  { id: 'u5', name: 'Dr. Lisa Cuddy', email: 'lcuddy@guardian.health', role: 'doctor', status: 'active', mfaEnabled: true, lastLogin: 'Oct 24, 2023 8:45 AM', department: 'Endocrinology' },
  { id: 'u6', name: 'Robert Chase', email: 'rc@guardian.health', role: 'staff', status: 'pending', mfaEnabled: false, lastLogin: 'Never', department: 'ICU' },
  { id: 'u7', name: 'Gregory House', email: 'house@guardian.health', role: 'doctor', status: 'suspended', mfaEnabled: false, lastLogin: 'Oct 1, 2023 11:20 AM', department: 'Diagnostics' },
  { id: 'u8', name: 'Allison Cameron', email: 'acameron@guardian.health', role: 'doctor', status: 'active', mfaEnabled: true, lastLogin: 'Oct 24, 2023 9:10 AM', department: 'Immunology' },
];

window.MOCK_PATIENTS = [
  { id: 'p1', name: 'Emily Chen', age: 34, condition: 'Hypertension', lastVisit: 'Oct 15, 2023', status: 'Stable' },
  { id: 'p2', name: 'Michael Scott', age: 45, condition: 'Type 2 Diabetes', lastVisit: 'Oct 20, 2023', status: 'Critical' },
  { id: 'p3', name: 'Jim Halpert', age: 42, condition: 'Asthma', lastVisit: 'Sep 05, 2023', status: 'Stable' },
  { id: 'p4', name: 'Pam Beesly', age: 38, condition: 'Pregnancy (2nd Trimester)', lastVisit: 'Oct 22, 2023', status: 'Monitoring' },
];

window.MOCK_AUDIT_LOGS = [
  { id: 'log1', hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', action: 'Login Success', user: 'admin@guardian.health', ip: '192.168.1.45', timestamp: 'Oct 24, 2023 8:12 AM', status: 'Verified' },
  { id: 'log2', hash: '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', action: 'Accessed Patient Record (P1)', user: 'doctor@guardian.health', ip: '10.0.0.12', timestamp: 'Oct 24, 2023 9:35 AM', status: 'Verified' },
  { id: 'log3', hash: '3a1e05d04cc6144d18ec030be82f09ba09d72d2b51296a84f3eb48c08fb180a6', action: 'Failed Login (Invalid MFA)', user: 'staff@guardian.health', ip: '45.22.11.90', timestamp: 'Oct 24, 2023 7:50 AM', status: 'Flagged' },
  { id: 'log4', hash: 'f2d81a260dea8a100dd517984e53c56a7523d96942a834b9cdc249bd4e8c7aa9', action: 'Updated Prescription (P2)', user: 'doctor@guardian.health', ip: '10.0.0.12', timestamp: 'Oct 24, 2023 9:40 AM', status: 'Verified' },
  { id: 'log5', hash: 'c90c3776e01a91e57c66cb1e839e94da98cff1315b80b2a8d38e078ba192518d', action: 'Role Modified (u4 → Senior Staff)', user: 'admin@guardian.health', ip: '192.168.1.45', timestamp: 'Oct 24, 2023 10:05 AM', status: 'Verified' },
  { id: 'log6', hash: 'a87ff679a2f3e71d9181a67b7542122c04c9900d03290167ad8c6e6f9af0ba78', action: 'Document Downloaded (Report)', user: 'patient@guardian.health', ip: '73.44.120.5', timestamp: 'Oct 23, 2023 2:55 PM', status: 'Verified' },
];

window.MOCK_SESSIONS = [
  { id: 'sess1', device: 'MacBook Pro (Chrome)', ip: '192.168.1.45', location: 'New York, USA', startedAt: 'Oct 24, 2023 8:12 AM', status: 'Active' },
  { id: 'sess2', device: 'iPhone 13 (Safari)', ip: '10.0.0.12', location: 'New York, USA', startedAt: 'Oct 24, 2023 9:30 AM', status: 'Active' },
  { id: 'sess3', device: 'Windows PC (Edge)', ip: '45.22.11.90', location: 'Moscow, RU', startedAt: 'Oct 23, 2023 11:15 PM', status: 'Terminated' },
];
