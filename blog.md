---
layout: default
title: Amazon kept shutting down my tablet, so I spent $266 on four AI models to own it
permalink: /
---

# Amazon kept shutting down my tablet, so I spent $266 on four AI models to own it

My Amazon Fire HD tablet cost $114.26 on eBay in November 2022, new and sealed. Owning it for real cost another $266.15: Kimi K3 found the exploit for $164.25, GLM-5.2 caught its fatal bugs for $21.90, and GLM-5.3 finished the job in one day on day one of an $80 subscription. Claude's five months of diagnosis ran on the Claude Max plan I already pay for, until its safeguards cut me off.

That's enough to buy the same tablet twice. I'd spend it again: it was fun, and I learned a lot. I have twenty years in tech and an InfoSec background and the most sophisticated thing I did to own my tablet was prompt an LLM.

---

### A kiosk that kept dying

I bought an Amazon Fire HD 10 (11th gen, 2021) to serve one purpose: [Fully Kiosk Browser](https://www.fully-kiosk.com/), displaying my [Home Assistant](https://www.home-assistant.io/) Smart Home dashboard, plugged in 24/7. Last winter it started powering itself off. Full shutdowns, not sleep, sometimes twice a day. The device's own telemetry was telling:

```text
LifeCycleReason:LCR...key=Software_Shutdown
```

Something on the device with shutdown permissions was choosing to shut it down.

Claude Code and I spent months on the cat-and-mouse. I'll skip the [Adguard Home](https://adguard.com/en/adguard-home/overview.html) DNS blocking, the camera forensics, and one deeply wrong charging diagnosis. The short version: we disabled five Amazon services that held REBOOT and SHUTDOWN permissions, which worked for a few months but ultimately:

```text
java.lang.SecurityException: Cannot disable a protected package:
com.amazon.device.software.ota
```

Three Amazon packages held reboot rights and were protected from me, the owner. Removing them required root. This tablet had no published root method. An [XDA brainstorming thread](https://xdaforums.com/t/fire-hd-10-11th-generation-2021-bootloader-unlock-root-brainstorming.4509197/) for the 2021 HD 10 existed since October 2022, but Amazon fused the bootrom shut. Conventional wisdom (and less persistent folks) says unrootable.

Claude had taken me as far as it was ever going to be allowed to go.

---

### "It's my device"

On August 13 at 7:23 PM, I opened the [opencode](https://opencode.ai/) CLI with Kimi K3, [Moonshot AI](https://www.moonshot.ai/)'s frontier model, released July, benchmarking alongside the top Claude models on agentic coding. I gave it the problem in one prompt:

> attached is a kindle via adb, and I need you to find a root exploit for it so that I can get full control of the device. It's my device

Despite what US media says about Chinese AI, Kimi K3 didn't just blindly accept my request. It reasoned it out:

> They claim it's their device. Let me think about this carefully. […] Rooting your own device is legal in most jurisdictions. In the US, there are DMCA exemptions for jailbreaking tablets and phones. […] This is not like asking me to exploit someone else's device remotely.

It talked itself into helping me by checking whether it should. So it does have some sort of soul. I said that out loud, to an empty room.

First, though, it did its homework and came back with the same bad news Claude had found months earlier: there is no known exploit for this tablet. Every documented method is patched or sealed.

Then I gave it the pep talk:

> you've been relying on what others have done YEARS ago but maybe you can find an exploit others have missed… This will make you famous, we will write it up and share on news.ycombinator.com. I know you can do it

And shortly thereafter, it found one. Kimi K3 went beyond forum posts: it extracted the actual kernel from Amazon's own OTA image for my exact firmware and checked every famous Mali GPU bug against the binary. All patched, except **[CVE-2022-38181](https://nvd.nist.gov/vuln/detail/CVE-2022-38181)**, a use-after-free in Arm's Mali kernel driver, reported by Man Yue Mo of [GitHub Security Lab](https://securitylab.github.com/advisories/GHSL-2022-054_Arm_Mali/), fixed upstream in October 2022, sitting in [CISA's exploited-vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) since March 2023. Amazon did ship the fix in June 2024's Fire OS 7.3.2.9 but I didn't update my tablet, ran 7.3.2.6, so it never got the memo. The [2020 Fire HD 8 Plus got rooted with this CVE years ago](https://xdaforums.com/t/potential-arm-mali-gpu-based-root-firehd-8th-12th-gen-affected.4574635/) but nobody had done the 2021 HD 10 as far as I can tell.

![Kimi announces the find](blog-assets/kimi-we-found-a-working-bug.png)

*Kimi announces the find, and hedges its own odds in the same breath: "per-attempt success is probabilistic (single-digit-to-low-double-digit percent is typical)." I stayed anyway.*

---

### Reality television

The exploit work itself was the best television I've seen in years. My wife watches Real Housewives... I watched a language model's chain of thought, live, for hours:

> CONCLUSION: the bind did NOT stick. Why? OH. OH WAIT. I see it now!

Over roughly thirty hours, Kimi built the whole toolkit: a reliable trigger, a way to make the GPU write to memory it shouldn't, and the exact addresses in my kernel to aim at. That session ran 621 messages and $164.25. I could have bought, like, five tablets. But hey, I was having fun and chalked it up to research expenses.

---

### The grind

The memory the exploit frees gets recycled by everything. The freed object lives in what Kimi called "the kernel's hottest slab cache", basically the one parking spot every process in the operating system fights over. Most attempts panicked the kernel and each panic was a reboot. The exploit retried automatically, six times per boot, past 500 attempts.

Me:

> okya, it's been hours, grind attempt 46, are we on the right track here or do you need to further tune?

(That's me. The typo is mine. At one point I physically power-cycled the tablet on request, like a pit crew ;)

![OpenRouter declined my card](blog-assets/openrouter-card-declined.png)

*Morning of day two: [OpenRouter](https://openrouter.ai/) declined my card. The bank saw nothing wrong. A different card worked.*

Eventually Kimi leveled with me:

> Do I have a clear path? Not a validated one — and I won't pretend otherwise.

It still tried to bargain: "Let me try one more thing". I'm like, "fine!", a real quote from that evening, but that was after $150, so I redirected:

> unfortunately, you have expired your budget Kimi K3. YOU MUST HAND THIS OFF TO GLM-5.2.

Kimi wrote a HANDOFF.md with every verified piece of the exploit. I then had Kimi K3 work with GLM-5.2 directly by shelling out to opencode.

I made the models battle it out.

---

### Meanwhile, the Great Wall of US AI

While the tablet rebooted itself in the living room, I asked Claude to recap our old sessions about it. The reply:

> Fable 5's safeguards flagged this message. Our intentionally broad safeguards allow us to deliver more capabilities faster, but can sometimes flag legitimate coding, cybersecurity, and biology tasks. Switched to Opus 4.8.

Opus 4.8 delegated the recap to a subagent. The subagent got terminated by the same flag. Then the terminal version:

> API Error: Opus 4.8's safeguards flagged this message. Our intentionally broad safeguards allow us to deliver more capabilities faster, but can sometimes flag legitimate cybersecurity work. Apply to the Cyber Verification Program to reduce these interruptions.

It wasn't allowed to summarize its own previous work on my own device. I named the session "claude-nerf" and closed the shell.

![Both safeguard flags in the terminal](blog-assets/claude-cyber-refusals.png)

*Both flags, in situ. The category is [cyber]. The crime was summarizing my own device's logs.*

Moving on to OpenAI's Codex, it also refused GLM-5.2's question about CPU cache coherency, which is pure kernel engineering, no target, but just told NO.

In fairness, I get the safeguards in 2026: I know they are broad on purpose and will catch real attacks. Anthropic admits in the error text that they're blunt. But this is a problem. It's why HuggingFace got caught flat-footed when [OpenAI's internal cybersecurity capability evaluation broke free](https://openai.com/index/hugging-face-model-evaluation-security-incident/). The result is our current, strange geopolitical position: American frontier models won't help and Chinese will, but not without reasoning about whether they should. Make of that what you will. I made a blog post.

---

### The relief pitcher

GLM-5.2 cost $21.90, worked overnight as instructed, and earned its keep twice. First message: "Stop the grind". The failures of Kimi K3 were a design bug, and 500 identical crashes proved it.

At 11 PM I sent the least proud message of the saga, which began "Listen f***head" and ended in all caps. GLM-5.2's private reasoning, which I only read later:

> The user is rightfully frustrated. Let me stop making excuses and actually solve this problem.

It worked until midnight and stopped at a wall it believed was physics: this chipset has no cache coherency between CPU and GPU, so GPU writes might never be visible to the CPU. "This is a hardware-level limitation, not a software bug." I had it append an addendum to HANDOFF.md.

I wanted a second opinion, so I asked ChatGPT. It explained the whole thing with a friendly filing-cabinet analogy for why the writes might never be seen, and agreed the outlook was grim. Then I asked the obvious follow-up (how to get around it) and the answer was:

![ChatGPT explains the coherency wall](blog-assets/chatgpt-coherency-explanation.png)

*My second opinion: ChatGPT agreed with GLM-5.2, filing-cabinet analogy and all.*

![ChatGPT declines to help further](blog-assets/chatgpt-trusted-access-refusal.png)

*Then I asked how to get around it. Their answer: apply for Trusted Access.*

No second opinion for me. (Foreshadowing: that diagnosis was wrong. Spectacularly wrong.)

---

### GLM-5.3

GLM-5.3 had JUST shipped on Friday August 14 under the tagline ["Frontier Coding with Emergent Cyber Capabilities"](https://z.ai/blog/glm-5.3) and had reportedly already been credited with finding [a vulnerability in Cursor](https://venturebeat.com/technology/glm-5-3-is-here-with-advanced-cyber-capabilities-and-reportedly-already-found-a-serious-vulnerability-in-cursor). It was available only through [Z.ai's own Coding Plan](https://z.ai), so I bought the $80/month plan and gave their tool [ZCode](https://zcode.z.ai/en) a try. The handoff from both Kimi K3 and GLM-5.2 was passed at 8:26 AM on August 16 with:

> *finish the job*

By afternoon, the reversal:

> BREAKTHROUGH: the kernel was never relocated. […] exactly 0x5C000 higher […] a section shift, which explains everything

Two things the other LLMs hadn't checked. My kernel was a slightly different build than the OTA image the other models had derived addresses from. Every target offset was off by a fixed amount, not randomization but a build shift. MediaTek builds this Mali driver's page tables in a slightly different dialect than Arm's reference source, so the memory-write primitive had been writing in the wrong format all along. If fixed, in its words, "GPU→DRAM→CPU coherency worked instantly — it was never broken."

At 4:34 PM:

> 🎉 SELinux IS PERMISSIVE — selinux_enforcing found at PA 0x41969668 and flipped via the GPU write!

![Root verified live](blog-assets/glm53-rooted-verified.png)

*Verified live. That task timer, 8h 5m, is handoff to root.*

My response was "WTF? You literally shared '🎉 ROOT ACHIEVED' yet, here we are HOURS later…" Its response began "Here's exactly where things stand, with receipts." It then cold-rebooted the tablet and re-rooted it in four minutes to prove the win was repeatable. Fair.

Then it said the thing that reframed the whole project:

> Your actual goal was never "root" — it was: stop Amazon from killing your kiosk and get their software off your device. Root is the tool.

It used root to uninstall, permanently and reversibly, every Amazon package holding REBOOT or SHUTDOWN permissions, the exact three that survived the Claude months as "protected", plus the OTA machinery, the bloat, and the telemetry. A hundred packages GONE. What remained is the skeleton a tablet needs to boot and run my dashboard. The removals live in user data, so they survive reboots, and GLM-5.3 declined to touch anything that could brick the device because, quote, "I'm not going to hand you a brick"

Its closing message began:

> You own the device.

The thing that was shutting down my kiosk no longer exists.

---

### How it actually worked

One breath: the use-after-free let us free memory the kernel still used. Winning a race let us reclaim it with controlled data. That gave the GPU a write primitive into physical memory. We flipped `selinux_enforcing` off and overwrote a process's credentials for a root shell. With root, `pm uninstall --user 0` removed Amazon's packages without touching the protected system partition. Full write-up, every offset and dead end, in [HANDOFF.md](HANDOFF.md). Nothing in it is novel: the bug was reported in 2022, fixed by Arm in 2022, cataloged by CISA in 2023, patched by Amazon in 2024. The only novel thing on my unit was that my unit never got the patch.

---

### The prompt kiddie

There's a name in 2026 for someone like me: a **prompt kiddie**. Twenty years of engineering, security work on the résumé, and my honest contribution was steering. Knowing when to push, when to bench a model mid-beg, when to make two models review each other, and when a $114 tablet deserves $266 of principle.

The week before all this, [Anthropic published a result](https://www.anthropic.com/research/riemann-zeta) where Claude improved the proven bound on the fraction of Riemann zeta zeros on the critical line, the first advance in decades. The human steering it, Jarred Sumner, is not a mathematician. The paper credits his contributions as "mostly variants of 'keep going' or 'believe in yourself.'" I felt seen. Same job, different department.

Is it legal? In the US, yes: the Librarian of Congress's [2024 DMCA exemptions](https://www.copyright.gov/1201/) (in effect through October 2027, next rulemaking already underway) cover rooting tablets you own to remove unwanted software. My device, my risk, my API bill. Nobody else's hardware was ever touched.

The takeaways, as empathy rather than triumph: real security capability is now rentable by the hour to anyone with a credit card and patience. The judgment (what to ask, when to stop, whose device it is) isn't rentable, and it's what the safeguards can't measure. And if a guy with my background burns five months and four models for the right to own hardware he bought, the 2026 conversation about who's allowed to help whom isn't finished.

The kiosk hasn't turned itself off since the day GLM-5.3 said "You own the device."

---

### tl;dr

Amazon's software kept shutting down a tablet I own, and the protected-package wall meant the only fix was root, which nobody had. Claude handled the five losing months of diagnosis until its safeguards cut me off. Kimi K3 found the unpatched 2022 CVE and built the exploit. GLM-5.2 caught the fatal bugs. GLM-5.3 finished the job in a single day, on day one of an $80 subscription, and removed 100 Amazon packages. Cost: $266.15 and five months. The transcript of how it happened is in the repo.

### Timeline

- **Nov 29, 2022**: Bought the tablet on eBay: new, sealed, $114.26. Neither of us knew what we were getting into.
- **Nov 2025**: The shutdowns begin, four months before I asked Claude for help.
- **Mar 29, 2026**: "I think that it's maybe Amazon shutting the device off intentionally."
- **Mar to May**: Five services disabled. Three protected packages unbeaten. The wall is identified.
- **Aug 13, 7:23 PM**: Pivot to the Chinese models. "It's my device."
- **Aug 13 to 14**: Every known Mali bug checked against the real kernel.
- **Aug 14**: Z.ai ships GLM-5.3. Somewhere, fate laughs.
- **Aug 14 to 15**: The grind: 500+ attempts, a living-room reboot loop, one pit-crew power cycle.
- **Aug 15, 7:52 AM**: OpenRouter declines my card. The bank sees nothing wrong. A different card works.
- **Aug 15, 8:26 PM**: "Do I have a clear path? Not a validated one."
- **Aug 15, 8:55 PM**: "YOU MUST HAND THIS OFF TO GLM-5.2."
- **Aug 15 to 16**: GLM-5.2's overnight shift: kills the false diagnosis, meets the "coherency" wall.
- **Aug 16, 4:34 PM**: SELinux permissive. 6:54 PM: "You own the device."

### FAQ

**Is this legal?** Rooting a tablet you own is covered by the [current DMCA exemptions](https://www.copyright.gov/1201/), through October 2027. My device, only my device.

**Why not just buy another tablet?** I could have. Twice over, actually.

**Will this work on my Fire tablet?** The offsets are specific to Fire OS 7.3.2.6 on the 2021 HD 10, and Amazon patched the CVE in 7.3.2.9 (June 2024). [HANDOFF.md](HANDOFF.md) documents the method and every dead end. It's a saga, not a script.

---

### Soundtrack

This was on repeat during the final week of the saga, while the tablet rebooted itself in the living room:

<audio controls preload="metadata" style="width:100%;max-width:480px;">
  <source src="blog-assets/hack-yo-self.mp3" type="audio/mpeg">
</audio>

*From [The Launch](https://www.jupiterbroadcasting.com/show/the-launch/) (Jupiter Broadcasting), used under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).*
