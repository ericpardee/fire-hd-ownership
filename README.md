# fire-hd-ownership

Owning the tablet I already bought.

In November 2022 I bought a Fire HD 10 (11th gen, 2021 model) on eBay for $114.26 to be a Home Assistant kiosk. It ran fine for years, then started powering itself off. The logs said why: Amazon's own software was issuing the shutdowns, and the packages responsible were protected from the device's owner. The only permanent fix was root — which nobody had ever achieved on this hardware.

Five months later, after a relay race between four AI models and $266.15 in API bills and subscriptions, the tablet is mine: root shell, SELinux permissive, and 100 Amazon packages removed (reversibly).

**Read the story: [blog.md](blog.md)**

## What's here

| Artifact | What it is |
|---|---|
| `blog.md` | The story (served as the site homepage) |
| `HANDOFF.md` | The full technical write-up (§9 = final exploit chain, §8 = GLM-5.2's addendum) |
| `REVIEW.md` | GLM-5.2's audit that stopped a doomed 500-attempt grind |
| `original-history.txt` | Sanitized transcripts of the Claude diagnosis months |
| `poc-28663/` | The CVE-2022-38181 proof-of-concept (Kimi K3's work) |
| `removed_manifest.txt` | The 100 Amazon packages that were removed |
| `grind*.sh`, `root_grind.sh` | The reboot-loop grinders |
| `hwparam.json`, `config.gz` | Device parameter/config dumps |

## Credits

- **Claude (Anthropic)** — months of shutdown diagnosis over ADB, up to the safeguard wall
- **Kimi K3 (Moonshot AI)** — found the unpatched CVE and built the exploit primitives
- **GLM-5.2 (Z.ai)** — the fatal-bug review, the fixed dump parser, the honest overnight dead-end
- **GLM-5.3 (Z.ai)** — finished the chain, flipped SELinux, removed the packages

## Legal & scope

- One device, owned by the author. No other hardware was ever touched.
- The vulnerability is CVE-2022-38181 ([GHSL-2022-054](https://securitylab.github.com/advisories/GHSL-2022-054_Arm_Mali/), GitHub Security Lab): public since 2022, fixed upstream October 2022, CISA KEV-listed March 2023, patched by Amazon in Fire OS 7.3.2.9 (June 2024). Nothing here is novel research.
- Rooting a tablet you own for interoperability/removing unwanted software is covered by the current US DMCA exemptions (effective Oct 2024 through Oct 2027).

## Not included

- The 1.06 GB firmware image (`ota_ps7326.bin`) and extracted partitions — too big for git, and Amazon's firmware isn't mine to redistribute.
- Third-party code cloned during research: [mtkclient](https://github.com/bkerler/mtkclient), the [GitHub Security Lab repo](https://github.com/github/securitylab) (Man Yue Mo's Mali research), and the [MTK kernel source](https://github.com/LCM-MTK/android_kernel_mediatek_mt6761) used as the kbase driver reference.

## Audio

The blog closes with a clip from [The Launch](https://www.jupiterbroadcasting.com/show/the-launch/) (Jupiter Broadcasting), used under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
