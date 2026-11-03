# Vercel-এ ফ্রি ডিপ্লয়

English: [DEPLOY_VERCEL.md](DEPLOY_VERCEL.md)

এই সেটআপের খরচ শূন্য এবং হাজার হাজার ইউজার সামলাতে পারে:

- **অ্যাপ:** Vercel Hobby (ডোমেইন ও HTTPS ফ্রি)
- **অ্যাকাউন্ট ও কেস:** Turso (ফ্রি ডাটাবেস)
- **ইমেইল (কনফার্মেশন ও রিসেট):** Resend বা Brevo বা যেকোনো SMTP (ফ্রি)

Hobby প্ল্যান **অ-বাণিজ্যিক** কাজের জন্য। বিনামূল্যের কমিউনিটি সার্ভিসে সমস্যা নেই। টাকা নিলে Pro লাগবে।

## ধাপগুলো

1. **GitHub:** কোড push করুন।
2. **Turso:** <https://turso.tech>-এ ডাটাবেস বানান। URL ও auth token নিন।
3. **ইমেইল:** Brevo-তে একটা sender ইমেইল ভেরিফাই করে API key নিন (Gmail ঠিকানা হলেও চলে)। অথবা Resend-এ ডোমেইন ভেরিফাই করুন।
4. **Vercel:** <https://vercel.com/new> থেকে repo import, Framework = **Other**।
5. **Environment Variables:** এগুলো বসান:
   - `AUTH_MODE=accounts`
   - `APP_SECRET` (`vercel-env.local.txt` ফাইলে বানানো আছে)
   - `PUBLIC_URL` (যেমন `https://osint.yourdomain.org`)
   - `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`
   - `MAIL_PROVIDER` (`brevo`/`resend`/`smtp`), `MAIL_FROM` (যেমন `NextCore BD <no-reply@yourdomain.org>`), `MAIL_API_KEY`
   - `OPERATOR_CONTACT`, `OPERATOR_JURISDICTION` (ইমেইল ও দেশ, legal পেজে দেখাবে)
6. **Deploy** চাপুন।
7. **Settings, Deployment Protection:** Vercel Authentication **বন্ধ** করুন, নাহলে মানুষকে আগে Vercel-এ লগইন করতে হবে।
8. **ডোমেইন:** Settings, Domains-এ ডোমেইন যোগ করে DNS রেকর্ড বসান। তারপর `PUBLIC_URL` ঠিক করে আবার ডিপ্লয় দিন।
9. **চেক:** সাইন-আপ করুন, ইমেইলের লিংকে ক্লিক করুন, লগইন করে একটা ফোন লুকআপ চালান, "পাসওয়ার্ড ভুলে গেছি" পরীক্ষা করুন।

সাইন-আপ "unavailable" বললে Vercel Logs-এ `ACCOUNTS UNAVAILABLE` খুঁজুন, কারণ লেখা থাকে। ইউজার বেশি হলে Vercel **Firewall**-এ `/login`, `/register`, `/forgot` ও `/api/*`-এর জন্য rate limit নিয়ম যোগ করুন।

`vercel-env.local.txt` কাউকে দেবেন না, এটা git-এ যায় না।
