# Selected investigations

Four of the pulses this engine produced, chosen for the decision each one
required rather than for the number of indicators it carried.

An OTX pulse description stops at 1024 characters, which is enough to say what
was found and not enough to say what was left out. That reasoning is the point
of this page. Every indicator named below is one that was published; the local
audit files are not in this repository and will not be, because they record
co-hosted third parties who are not part of any campaign.

---

## VShell: eight /27 blocks filled end to end at one provider

[Pulse](https://otx.alienvault.com/pulse/6aaa81ca5b399ed79277b44b) · 16 September 2026 · 8 CIDR blocks

A fleet of VShell command and control hosts sitting in contiguous runs at one
provider. Published as eight /27 blocks rather than as 232 individual
addresses, because a /27 expands to its hosts losslessly and publishing both
would have added 232 derivable rows while leaving the claim ambiguous. A block
was published only where at least 29 of its 30 usable addresses were already
listed.

The enclosing /21 was withheld. 1816 of its 2048 addresses carry no evidence at
all, and the controls established uniform ownership, not that the rest of the
range is in use or hostile.

Every address came from a single ThreatFox reporter, so one reporter is one
opinion and VirusTotal was used as the second source. The strength is not the
depth of any one detection, which ran 3 to 8 of roughly 55, but that 87 of 87
newly checked addresses showed detections with no exceptions.

**What was wrong.** The pulse carried a prediction of its own: that the block
offset would recur in adjacent /24s. Testing it gave 18 matches against 27.3
expected by chance, which is below chance. Five of nine multi-address /24s were
perfectly contiguous but at other offsets, so the operator takes blocks while
the position belongs to the allocation. The hunt rule in the description had
been drafted telling defenders to watch an offset that does not recur, and was
rewritten before publication.

---

## Grandoreiro against Mexico: cloud C2 and rented delivery hosts

[Pulse](https://otx.alienvault.com/pulse/6aab5ace3c70403848af5abc) · 17 September 2026 · 7 indicators

Two tiers kept apart: command and control on three cloud instances, each
listening on exactly three high ports, and payload delivery on separately
rented VPS hosts reached by their provider-assigned hostnames.

The family is Brazilian in origin and the feed tags this activity as targeting
Mexico. The description says so explicitly, because the tag describes who is
being hit and not where the operator sits, and conflating the two is how a
pulse ends up asserting attribution it has not earned.

A dynamic DNS name ties the tiers together, having resolved to two of the three
C2 hosts inside one week. The feed classifies it only as unknown malware, so
the pulse states that the link rests on shared hosting and timing rather than
on anyone's label.

**What was left out.** Two candidates. One had no evidence newer than 146 days,
outside the currency window, so it described a host the campaign had already
left. The other was a live host behind a delivery name, but only one weak
source carried it, below the two-source bar applied to everything else in the
set. Passive DNS on all three C2 addresses showed no third-party tenant, so
nothing published here lands on a bystander. Cloud addresses recycle, so that
holds now rather than indefinitely.

---

## Mispadu (Malteiro, G1026): Latin America banking trojan sample set

[Pulse](https://otx.alienvault.com/pulse/6a9c931eaaa920f1301b969a) · 5 September 2026 · 5 hashes

Detection content rather than a blocklist, and the pulse says so. No command
and control address is published because none was found, and the samples were
not detonated. Blocking five hashes buys little when the delivery chain
rebuilds, so the value is the ATT&CK mapping and the behaviour to watch for:
mail-delivered attachments running through HTA or Visual Basic, injection into
browser processes, then reads of browser credential stores.

Mispadu is sold as a service. A sample therefore places the family and its
platform, not necessarily the operators who built it, and the campaign behind
any given sample may be a customer's. The pulse records that caveat rather
than naming the group as the operator of everything the family touches.

This is the one entry where the engine did the whole expansion unaided: one
seed, the group name, and every published indicator was reached and scored by
the chain rather than added by hand.

---

## German public procurement: FileFix lures, and what happened next

[First pulse](https://otx.alienvault.com/pulse/6ac7e464e441c5b8f83f0700) · 8 October 2026 · 18 indicators
[Follow-up](https://otx.alienvault.com/pulse/6acd68a608b12071ccd4e2b8) · 12 October 2026 · 7 indicators

A cluster of lookalike domains impersonating German public tendering and
vehicle-fleet procurement, including one imitating the federal armed forces
equipment office. Three URLs reported to a feed became ten domains across two
hosts, linked by one TLS certificate covering three of the names and by the
same lure path on eight of them.

**What was left out.** The second host was shared with unrelated infrastructure
and was withheld. So were three parent domains belonging to real companies
whose DNS had been used against them: the published indicators are the
subdomains an attacker added to those zones, not the companies' own names, and
the description says to block the hostname and leave the parent alone.

The export tooling also proposed two certificates that belonged to the victim
companies, one of them a wildcard covering an entire firm's domain. Publishing
that would have flagged all of their legitimate traffic. Both were removed by
hand before upload.

**What was wrong.** The first pulse told defenders to hunt one lure path. Four
days later the operator stood up a replacement domain on the same host serving
that path and a second one, so the original rule caught half its URLs. The
follow-up says so. It also recorded a prediction that the operator would stay
on that provider, which held for about a day before the name moved twice more,
to hosting in two other countries. That correction is in the published pulse
rather than left standing.
