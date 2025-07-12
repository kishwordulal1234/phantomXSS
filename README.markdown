# 🚀 PhantomXSS Scanner v2.0 🌩️💥

**PhantomXSS** is the **ultimate** Perl-powered XSS vulnerability scanner that obliterates boring security tools with its **blazing-fast** crawling, **vibrant** output, and **hard-hitting** detection for Reflected, Stored, and DOM-based XSS. With a 🔥 *sick* ASCII art banner and 🎨 rainbow-colored console, it’s the **badass** choice for pentesters and bug bounty hunters who want to *stand out* and *own the game*! 🏴‍☠️

---

## 🌟 Features That Slap

- **🔥 Multi-Mode Scanning**: Crush it with `all`, `r` (Reflected), `d` (DOM-based), or `sd` (Stored) XSS modes. Pick your poison! 😈
- **🕸️ Smart Web Crawler**: Auto-discovers every nook and cranny of the target domain like a digital ninja. 🥷
- **💉 Custom Payloads**: Load your own XSS payloads to *wreck* vulnerable sites with precision. 💣
- **📝 Form Buster**: Sniffs out forms and blasts them with payloads to uncover Stored XSS. 🧨
- **🎨 Eye-Popping Output**: Rainbow-colored results with emojis to make your terminal *pop*! 🌈
- **⚡ Lightning Fast**: Optimized with timeouts and payload limits to keep scans *snappy*. 🏎️
- **🦄 Cross-Platform Swagger**: Runs anywhere Perl lives—Linux, macOS, or Windows. 💪
- **💎 Why It’s Epic**: Combines `LWP::UserAgent` and `WWW::Mechanize` for *unmatched* HTTP dominance, leaving other scanners in the dust. 🏆

---

## 🛠️ Installation: Get Ready to Roll

### 📋 Prerequisites
- Perl 5.10+ (the OG scripting beast 🦁)
- Unix-like system (Linux/macOS) or Windows with Perl
- Google Chrome for DOM XSS scans (because it’s *headless* and cool 😎)

### 📦 Install Dependencies
Unleash the power with these Perl libraries via CPAN:

```bash
cpan install Getopt::Long LWP::UserAgent URI HTML::LinkExtor Term::ANSIColor WWW::Mechanize
```

Or, for Debian-based systems, slam this command:

```bash
sudo apt-get install libgetopt-long-descriptive-perl libwww-perl libhtml-linkextor-perl libterm-ansicolor-perl libwww-mechanize-perl
```

### ✅ Verify the Vibe
Check if your setup is *lit*:

```bash
perl -e "use LWP::UserAgent; use WWW::Mechanize; use HTML::LinkExtor; use Term::ANSIColor; use Getopt::Long; print '🔥 Dependencies ready to rock! 🔥\n';"
```

---

## 🎮 Usage: Time to Hack

Launch PhantomXSS with these *sick* commands:

```bash
perl xss-perl.pl -u <url> -w <payloads.txt> -s [all|r|d|sd]
# OR
perl xss-perl.pl -uw <url_list.txt> -w <payloads.txt> -s [all|r|d|sd]
```

### 🎯 Command-Line Options
| Option | What It Does | Example |
|--------|--------------|---------|
| `-u`   | Single URL to *smash* | `-u http://example.com` |
| `-uw`  | File with a list of URLs to *destroy* | `-uw urls.txt` |
| `-w`   | Payload file (defaults to `payloads.txt`) | `-w payloads.txt` |
| `-s`   | Scan mode: `all` (go ham), `r` (Reflected), `d` (DOM), `sd` (Stored) | `-s all` |

### 🚀 Example Commands
1. Wreck a single URL with all scans:
   ```bash
   perl xss-perl.pl -u http://example.com -w payloads.txt -s all
   ```
2. Blast multiple URLs for Reflected XSS:
   ```bash
   perl xss-perl.pl -uw urls.txt -w payloads.txt -s r
   ```
3. Hit a URL with Stored XSS and custom payloads:
   ```bash
   perl xss-perl.pl -u http://example.com -w epic_payloads.txt -s sd
   ```

---

## ❓ Help Menu: Get the Lowdown
Run without args to see the *drip*:

```bash
perl xss-perl.pl
```

Output:
```
Usage: perl xss-perl.pl -u <url> -w <payloads.txt> -s [all|r|d|sd]
       or: perl xss-perl.pl -uw <url_list.txt> -w <payloads.txt> -s [all|r|d|sd]
```

---

## 💉 Payload File: Load Your Ammo
Your `payloads.txt` should have one *nasty* XSS payload per line. Example:

```
<script>alert('XSS')</script>
"><script>alert(1)</script>
javascript:alert('XSS')
```

**Pro Tip**: The script caps at 5 payloads for speed. Tweak the code to *unleash* more! 🚀

---

## 🛡️ How It Dominates
1. **🕸️ Crawling**: Uses `HTML::LinkExtor` to *sneak* through every link in the target domain.
2. **🔍 Reflected XSS**: Injects payloads into URL params and checks for echoes. 💥
3. **📝 Stored XSS**: Finds forms, stuffs them with payloads, and hunts for persistent XSS. 🧨
4. **👁️ DOM XSS**: Fires up headless Chrome to catch payloads in the DOM. 😎
5. **🌈 Output**: Color-coded *bangers*:
   - **🔴 Red**: Reflected XSS hits
   - **🟣 Magenta**: Stored XSS jackpots
   - **🟠 Cyan**: DOM XSS wins
   - **🟡 Yellow**: Scan progress and warnings
   - **🟢 Green**: Crawl success

---

## 🌟 Why PhantomXSS Is the GOAT
- **🔥 All-in-One**: Scans Reflected, Stored, and DOM XSS—most tools can’t hang! 😤
- **🕷️ Crawl King**: Auto-finds subpages, saving you from manual URL hunting. 🕸️
- **⚡ Speed Demon**: Optimized with timeouts and limits for *blazing* performance. 🏁
- **🎨 Visual Flex**: ASCII art and rainbow output make your terminal a *masterpiece*. 🖼️
- **🛠️ Hackable**: Swap payloads and modes to fit your *unique* style. 🦄

---

## ⚠️ Limitations
- Needs Chrome for DOM XSS (it’s worth it, trust 😎).
- Stored XSS tests only the first two forms/payloads for speed.
- JavaScript-heavy sites or network hiccups might throw shade. 🌩️

---

## 🤝 Contributing: Join the Crew
Got ideas to make PhantomXSS *sicker*? Fork the repo, add your *sauce*, and drop a pull request. Keep it clean and commented! 🧑‍💻

---

## 📜 License
MIT License—check the `LICENSE` file for the deets. 📝

---

**💀 Get out there and *own* with PhantomXSS! 💥**