# DonorLink Global — Mobile Upload Edition

A real Supabase-backed blood-donor coordination application packaged as only **4 root files** so it is easy to upload from a phone.

## Files

1. `index.html` — complete app UI + application logic
2. `config.js` — your two public Supabase browser values
3. `schema.sql` — database, security policies, notifications and secure RPCs
4. `README.md` — these instructions

There are **no folders**, no npm install, no build command, and no service-role secret in the frontend.

## First-time setup

### 1) Supabase
Create a new Supabase project. Open **SQL Editor**, paste the full contents of `schema.sql`, and Run it once.

Open **Project Settings → API** and copy:
- Project URL
- anon key / publishable key

Open `config.js` and replace the two placeholder values. The anon/publishable key is public by design. **Never use the service_role key in `config.js`, GitHub, or browser code.**

### 2) Authentication URL
In Supabase **Authentication → URL Configuration**, set your Site URL to your final Vercel URL after the first deployment. Add the same Vercel URL as an allowed redirect URL.

### 3) GitHub mobile upload
Create a repository, choose **Add file → Upload files**, select these four files, then commit. Because everything is at root, you do not need to recreate folders on mobile.

### 4) Vercel
Import the GitHub repository into Vercel. Framework can remain **Other**. There is no package.json and no build step; Vercel can serve the root `index.html` as a static site. No environment variables are needed because the two public browser values are in `config.js`.

### 5) Create the first admin
Register a normal account in DonorLink, then in Supabase SQL Editor run this once, replacing the email:

```sql
update public.profiles p
set role = 'admin'
from auth.users u
where p.id = u.id and lower(u.email) = lower('YOUR_EMAIL@example.com');
```

Public signup cannot create an admin account. Admin changes are protected by database functions.

## Safety model

DonorLink coordinates voluntary blood donation. It does not determine medical eligibility, guarantee availability, sell blood, or replace hospital/blood-bank screening. Exact donor locations are not exposed to requesters. A verified organization means the organization account was reviewed in DonorLink; it is not a medical accreditation by DonorLink.

## Main functions

- Email/password signup and login
- Donor/requester/hospital/blood-bank/NGO roles
- Donor blood group, availability, radius and GPS update
- Emergency blood-request creation and status management
- Exact-group donor matching with distance/city fallback
- Automatic in-app notifications to matching active donors
- Donor volunteer / cancel response
- Request-owner accept / decline / complete response
- Private chat after acceptance
- Organization application and admin verification
- Verified-organization donation confirmation code
- Notifications inbox
- English/Hindi/Gujarati interface option
- Privacy and safety information
- Self-service account deletion
- Row Level Security and database-level state guards

## Recommended first launch

Start operationally in one country/region, verify hospitals/blood centres carefully, test the complete request-to-donation workflow, and only then open additional countries. Country-specific donor eligibility remains the responsibility of the authorized blood service.
