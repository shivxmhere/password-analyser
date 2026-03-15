# 🔐 Password Strength Analyser + Secure Generator

> Day 3/35 — #35DaysOfProjects by Shivam Singh | IIT Patna

Not just weak/strong. Real cybersecurity analysis powered by NIST guidelines.

## 🔗 Live Demo

[https://passwordanalyser-day3-iitpatna.vercel.app](https://passwordanalyser-day3-iitpatna.vercel.app)

## ✨ Features

- Real-time password analysis as you type
- Entropy calculation in bits
- Crack time estimation for 3 attack types (Online, Offline, GPU Cluster)
- Pattern detection: keyboard walks, l33tspeak, sequential numbers, common words
- NIST rule checklist with live pass/fail feedback
- Cryptographically secure password generator using `crypto.getRandomValues()`
- Password vault with localStorage (max 10 entries)
- Dark glassmorphism UI with animated meters and micro-interactions

## 🛠️ Tech Stack

HTML · CSS · Vanilla JavaScript · Web Crypto API

## 📊 What I Learned

- Entropy and information theory basics
- NIST SP 800-63B password guidelines
- Web Crypto API for true randomness
- Fisher-Yates shuffle algorithm
- Pattern detection with regex
- Crack time estimation mathematics

## 🚀 Run Locally

```bash
# Just open in your browser — zero setup required
open index.html
```

## 📁 Project Structure

```
password-analyser/
├── index.html      # Main HTML structure
├── style.css       # Complete design system
├── app.js          # Full analysis engine (pure vanilla JS)
├── vercel.json     # Vercel deployment config
├── README.md       # This file
└── .gitignore      # Git ignore rules
```

## 📁 Deploy

```bash
vercel --name passwordanalyser-day3-iitpatna --prod
```

---

Built with 💜 as part of **#35DaysOfProjects**
