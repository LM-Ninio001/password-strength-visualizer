# Password Strength Visualizer

[![Test and deploy](https://github.com/LM-Ninio001/password-strength-visualizer/actions/workflows/deploy.yml/badge.svg)](https://github.com/LM-Ninio001/password-strength-visualizer/actions/workflows/deploy.yml)

A fast, private, single-page app that shows how strong a password is, and *why*, with live visual feedback as you type. Everything runs in your browser. The password is never sent anywhere.

**Live demo:** https://lm-ninio001.github.io/password-strength-visualizer/

<!-- Screenshot: save one as docs/screenshot.png, then replace the placeholder below with:
![Screenshot of the Password Strength Visualizer](docs/screenshot.png) -->
> 📸 *Screenshot coming soon.*

Plain HTML, CSS and JavaScript (ES modules). No framework, no build step, no dependencies.

## Features

- **Password input** with show/hide toggle and copy button
- **Animated strength meter** in five levels (Very weak → Very strong), with colour gliding smoothly from red to green and always paired with a text label
- **Entropy estimate** in bits: character pool × length, minus penalties for detected patterns
- **Time to crack** in plain words for two attacks: online throttled (100 guesses/s) and offline fast hash (10 billion guesses/s)
- **Live checklist:** length ≥ 12, lowercase, uppercase, number, symbol, not a common password
- **Pattern detection:**
  - the top 1,000 common passwords (bundled locally)
  - keyboard walks (`qwerty`, `asdf`, `12345`)
  - repeated characters (`aaaa`)
  - alphabet and number runs (`abcd`, `6789`)
  - years and dates (`1998`, `12/05/2024`)
  - leetspeak versions of common words (`p@ssw0rd`)
  - dictionary words from the passphrase list
- **Plain-English tips** that change as you type ("Add 4 more characters", "Avoid keyboard patterns")
- **Composition chart:** a donut chart of lowercase, uppercase, digits, symbols and Unicode/emoji
- **Generator** for random-character passwords or passphrases, using `crypto.getRandomValues` (never `Math.random`)
- **"Check if leaked"** via the Have I Been Pwned k-anonymity API (only 5 characters of a hash are sent)
- Dark theme with a light toggle, responsive down to phone width, keyboard accessible, screen-reader announcements, and support for `prefers-reduced-motion`

## How it works

### Entropy

A password of length *L* drawn at random from a pool of *N* possible characters has *N^L* combinations, which is **L × log₂(N) bits** of entropy. The pool is the sum of the character classes used:

| Class | Pool |
| --- | --- |
| Lowercase `a–z` | 26 |
| Uppercase `A–Z` | 26 |
| Digits `0–9` | 10 |
| ASCII symbols and space | 33 |
| Anything else (accents, emoji, other scripts) | 100 |

Characters are counted as Unicode code points, so 🔒 is one character, not two.

### Pattern penalties

People don't pick characters at random, and attackers know it. Each detector finds segments an attacker would guess as a *unit*, and gives each segment a much smaller cost:

| Pattern | Approximate cost of the segment |
| --- | --- |
| Common password at rank *r* | log₂(*r*) + 1 bit per capitalisation choice |
| Leetspeak word | as above + 1 bit per substitution |
| Dictionary word (passphrase list) | log₂(list size) ≈ 8.9 bits |
| Keyboard walk | log₂(starting keys × 2 directions) + log₂(length) |
| Repeated character | log₂(100) + log₂(length) |
| Alphabet/number run | log₂(26 or 10) + 1 (direction) + log₂(length) |
| Year / full date | log₂(200) ≈ 7.6 / log₂(365 × 200) ≈ 16.2 bits |

Matches can overlap, so a small dynamic program finds the **cheapest way to cover the whole password** with either single random characters (log₂(N) bits each) or pattern matches. That minimum is the reported entropy, and the difference from L × log₂(N) is shown as the pattern penalty. A password that *is* a known common password is always rated Very weak.

### Time to crack

An attacker needs on average half the search space, **2^(bits − 1)** guesses, divided by the guess rate: 100/s for a throttled online login, or 10¹⁰/s for an offline attack on a fast hash like unsalted MD5 or SHA-1.

### Strength levels

| Level | Entropy |
| --- | --- |
| Very weak | < 28 bits |
| Weak | 28–40 bits |
| Fair | 40–60 bits |
| Strong | 60–80 bits |
| Very strong | ≥ 80 bits |

These are estimates, in the spirit of tools like zxcvbn, not guarantees.

## Privacy

- All analysis runs locally in your browser. The password is **never** sent, logged (`console`), stored (`localStorage`, cookies) or put in the URL. The only thing saved is your light/dark theme choice.
- The optional leak check uses [k-anonymity](https://haveibeenpwned.com/API/v3#PwnedPasswords): the password is hashed with SHA-1 via Web Crypto, and **only the first 5 hex characters** of the hash are sent to `api.pwnedpasswords.com`. The API returns every leaked hash with that prefix (padded with dummy entries so response size gives nothing away), and the match is done in your browser.
- A strict Content Security Policy blocks any script that isn't from this site, and allows network connections only to the HIBP range API.

## Run locally

ES modules need to be served over HTTP (not opened as `file://`):

```sh
git clone https://github.com/LM-Ninio001/password-strength-visualizer.git
cd password-strength-visualizer
python3 -m http.server 8000
```

Then open http://localhost:8000.

## Run the tests

Uses Node's built-in test runner (Node 20+), with no dependencies to install:

```sh
npm test        # or: node --test
```

The tests cover the entropy maths, every pattern detector, crack-time formatting, the generator (including that `Math.random` is never called), the leak-check request (only the hash prefix is sent), and edge cases: empty input, emoji and other Unicode, and a 10,000-character password.

## Project structure

```
index.html             markup and accessibility hooks
styles.css             theme tokens, layout, motion
src/strength.js        pure analysis: pool, entropy, crack time, checklist, tips
src/patterns.js        pattern detectors
src/generator.js       secure password / passphrase generation
src/pwned.js           SHA-1 + HIBP range lookup
src/ui.js              DOM rendering and events
src/data/              common-password list and passphrase word list
test/                  node:test suites
```

## Credits

- Common-password list: [SecLists](https://github.com/danielmiessler/SecLists) (MIT), top 1,000 entries
- Breach data: [Have I Been Pwned](https://haveibeenpwned.com/) Pwned Passwords

## License

[MIT](LICENSE)
