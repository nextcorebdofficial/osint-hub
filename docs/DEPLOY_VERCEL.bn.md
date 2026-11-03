# Vercel-এ ডিপ্লয় করা

English: [DEPLOY_VERCEL.md](DEPLOY_VERCEL.md)

Vercel serverless, তাই ল্যাপটপ বা VPS-এর চেয়ে কিছু বিষয় আলাদা:

- Investigation একটা রিকোয়েস্টের ভেতরেই শেষ হয় (প্রগ্রেস কাউন্টার নেই)।
- Cases রাখতে ফ্রি **Turso** ডাটাবেস লাগে। না দিলে ডেটা মুছে যায়।
- Audit log Vercel-এর Logs-এ `AUDIT` লাইন হিসেবে দেখা যায়।
- Hobby প্ল্যান শুধু **অ-বাণিজ্যিক** কাজের জন্য।

## ধাপগুলো

1. **GitHub-এ কোড দিন:** একটা repo বানিয়ে `git remote add origin ...` ও `git push -u origin main`। চাইলে private repo।
2. **Turso:** <https://turso.tech>-এ ডাটাবেস বানান, URL ও auth token নিন।
3. **Vercel-এ Import:** <https://vercel.com/new> থেকে repo ইমপোর্ট করুন, Framework = **Other**।
4. **Environment Variables:** প্রজেক্ট ফোল্ডারের `vercel-env.local.txt` ফাইলে `APP_PASSWORD` ও `APP_SECRET` আগে থেকেই বানানো আছে। ওখান থেকে কপি করে Vercel-এ বসান। এর সাথে বসান `OPERATOR_NAME`, `OPERATOR_CONTACT`, `OPERATOR_JURISDICTION`, `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`, `CASE_RETENTION_DAYS=30`।
5. **Deploy** চাপুন। পরে প্রতিটি `git push` অটো ডিপ্লয় হবে।
6. **ডোমেইন:** Settings, Domains-এ ডোমেইন যোগ করে Vercel-এর দেখানো DNS রেকর্ড বসান। HTTPS অটো।
7. **চেক:** `/api/health`, `/legal/privacy`, লগইন করে একটা ফোন লুকআপ ও কেস সেভ করে দেখুন।

`vercel-env.local.txt` ফাইল কাউকে দেবেন না, এটা git-এ যায় না।
