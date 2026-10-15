# Featured investigations

Some featured investigations conducted by the Pivot Engine

---

## VShell: eight /27 blocks filled end to end at one provider

[Pulse](https://otx.alienvault.com/pulse/6aaa81ca5b399ed79277b44b) · 16 September 2026 · 8 CIDR blocks

**Target.** A VShell command and control fleet at a single provider, reached by
querying the family rather than any one address, so the unit of analysis was
the cluster from the start.

**What came out of it.** 232 listed addresses sitting in contiguous runs. Eight
/27 blocks were dense enough to publish as blocks: in each, at least 29 of the
30 usable addresses were already listed as C2. Publishing the blocks rather
than the hosts says something the host list cannot, which is that the operator
holds whole allocations rather than scattered machines.

**Insights.** Every address traced to one ThreatFox reporter, and one reporter
is one opinion however many rows it produces, so VirusTotal became the second
source. The strength there is not depth, since individual detections ran 3 to 8
of roughly 55, but consistency: 87 of 87 newly checked addresses carried
detections with no exceptions. A control group of eight unlisted addresses in
the same range resolved to the same owner and carried no detections, which is
what separates a dense block from a provider that simply looks bad.

The pulse also carried a prediction: that the block offset would recur in
adjacent /24s. It did not. Testing gave 18 matches against 27.3 expected by
chance, below chance, and five of nine multi-address /24s were perfectly
contiguous at other offsets. The operator takes blocks; the position belongs to
the allocation. The hunt rule had been drafted around that offset and was
rewritten before publication.

**Withheld.** The enclosing /21, because 1816 of its 2048 addresses carry no
evidence and the controls established common ownership rather than hostility.
The 232 individual addresses were also left out, since a /27 expands to its
hosts losslessly and publishing both would have added derivable rows while
making the claim ambiguous.

---

## Grandoreiro against Mexico: cloud C2 and rented delivery hosts

[Pulse](https://otx.alienvault.com/pulse/6aab5ace3c70403848af5abc) · 17 September 2026 · 7 indicators

**Target.** Grandoreiro infrastructure that a feed tagged as targeting Mexico.

**What came out of it.** Two tiers that do not look alike. Command and control
ran on three cloud instances, each listening on exactly three high ports.
Payload delivery ran separately on rented VPS hosts reached by their
provider-assigned hostnames. A dynamic DNS name tied the tiers together: it
resolved to two of the three C2 hosts inside a single week.

**Insights.** The family is Brazilian in origin and the targeting is Mexican,
and the pulse says both, because a targeting tag describes who is being hit and
not where the operator sits. Collapsing those two is how a pulse ends up
claiming attribution it has not earned.

The dynamic DNS link is stated as what it is. The feed classifies that name
only as unknown malware, so the connection rests on shared hosting and timing,
not on anyone's label, and a reader can weigh it accordingly.

Two of the three delivery hosts stopped resolving within forty days of being
reported. They stay in the pulse anyway: blocking them achieves nothing now,
but they remain worth searching for in historical logs. Because the provider
issues those hostnames per instance and retires them with the VPS, a dead one
cannot later be handed to an unrelated customer.

**Withheld.** Two candidates. One had no evidence newer than 146 days, which
describes a host the campaign had already left. The other was live behind a
delivery name but carried only one weak source, below the two-source bar
applied to everything else in the set. Passive DNS on all three C2 addresses
showed no third-party tenant, so nothing published lands on a bystander, and
that holds now rather than indefinitely because cloud addresses recycle.

---

## Mispadu (Malteiro, G1026): Latin America banking trojan sample set

[Pulse](https://otx.alienvault.com/pulse/6a9c931eaaa920f1301b969a) · 5 September 2026 · 5 hashes

**Target.** Mispadu, the banking trojan built and operated by Malteiro, seeded
by nothing more than the group name.

**What came out of it.** Five samples and an ATT&CK mapping to the techniques
MITRE attributes to G1026. This is the one investigation here where the engine
did the whole expansion unaided: one seed, six pivots, and every published
indicator reached and scored by the chain rather than added by an analyst.

**Insights.** The deliverable is detection content, not a blocklist, and the
difference matters. Five hashes buy little when the delivery chain rebuilds, so
the pulse describes the chain instead: mail-delivered attachments running
through HTA or Visual Basic, injection into browser processes, then reads of
browser credential stores. Mispadu checks system language before running, which
is the single clearest behaviour to detect on, and lures are Spanish and
Portuguese.

Mispadu is sold as a service. A sample therefore places the family and its
platform, not necessarily the operators who built it, and the campaign behind
any given sample may belong to a customer. The pulse carries that caveat rather
than naming the group as the author of everything the family touches.

**Withheld.** Nothing, and the distinction is worth drawing. No command and
control address appears because none was found, not because one was held back,
and the samples were not detonated. An absence reported as a decision would
claim more care than was taken.

---

## German public procurement: FileFix lures, and what happened next

[First pulse](https://otx.alienvault.com/pulse/6ac7e464e441c5b8f83f0700) · 8 October 2026 · 18 indicators
[Follow-up](https://otx.alienvault.com/pulse/6acd68a608b12071ccd4e2b8) · 12 October 2026 · 7 indicators

**Target.** Three URLs reported to a feed in one morning, all German domains
serving the same path.

**What came out of it.** Ten domains across two hosts, including lookalikes for
federal e-tendering, a procurement portal, and the armed forces equipment
office. One TLS certificate covered three of the names outright. Eight served
an identical lure path. Four days later the operator stood up a replacement on
the same host, serving that path and a second one, and within a day of the
follow-up the new name moved twice more, to hosting in two other countries,
taking a newly compromised company's subdomain with it.

**Insights.** Every campaign domain resolved through one provider's
nameservers and mail, which is what separated them from the unrelated tenants
renting the same box. Registration history then separated the attacker's own
lookalikes from real companies whose DNS had been turned against them: the
operator was compromising hosting-provider accounts and repointing records,
not typosquatting, and the follow-up found the same pattern at a second German
provider.

The first pulse told defenders to hunt one lure path. When the replacement
served two, that rule caught half its URLs, and the follow-up says so. It also
recorded a prediction that the operator would stay on one provider. That held
for about a day. Both corrections sit in the published pulses rather than
being left to stand.

**Withheld.** The second host, shared with unrelated infrastructure. Three
parent domains belonging to real companies, where the published indicators are
the subdomains an attacker added to their zones and the description says to
block the hostname and leave the parent alone. And two certificates the export
tooling proposed that belonged to the victims rather than the operator, one of
them a wildcard covering an entire firm's domain, which would have flagged all
of that company's legitimate traffic.

---

## Guildma C2 named from telenovelas and Brazilian flowers

[Pulse](https://otx.alienvault.com/pulse/6ad049e3c5c151c394656706) · 14 October 2026 · 26 indicators · TLP:GREEN

**Target.** Guildma and Astaroth, the Brazilian banking trojan family, reached
by querying the family tags rather than any single address.

**What came out of it.** Two registration vocabularies, used by one operator.
Eleven `.sbs` domains, of which nine are Spanish-language telenovela titles,
one registered in its Portuguese form rather than the Spanish original. Four
`.cfd` domains pairing the Portuguese word for flowers with a botanical genus,
one of them a tree known in Brazil as chuva-de-ouro. Beneath both sit generated
labels that are pronounceable rather than random. Two live staging hosts on
provider-assigned VPS hostnames, one Guildma and one Grandoreiro, stood up a
day apart.

**Insights.** The naming defeats entropy-based detection by construction. A
real word scores like a brand on entropy, vowel ratio and consonant runs, so a
classifier tuned for random-looking names reads the registrable layer as
ordinary. The operator has split the problem: dictionary words where
registration costs money and a human might look, generated labels beneath,
where neither applies. That also makes the signature generative rather than
descriptive, because a wordlist can be enumerated and watched ahead of use.

The flower set then did something the telenovela set did not. In September it
gained click-tracking and sending subdomains with a DKIM selector for each
domain, so year-old trojan infrastructure was rebuilt as authenticated mail.
Those mail names carry the pulse's GREEN label: no free feed holds them, and a
reader without a licence cannot check them.

What the vocabulary does not establish is nationality, and the pulse does not
claim it. Televisa exported these titles across Latin America and into Brazil
in Portuguese dubs. If anything the Portuguese-form registration points the
same way the family already does.

**Withheld.** The address the domains now park on, which carries 68 unrelated
tenants. A second staging host shared with an unrelated German campaign. Two
provider addresses, since the per-instance hostnames retire with the VPS and
the addresses pass to the next customer. And a certificate the export tooling
proposed that belonged to the hosting provider rather than this operator,
which would have flagged every customer on it.

The mail subdomains were nearly left out too. On first reading they could have
been the parking service's own configuration, and publishing them on that
assumption would have been a guess. Testing the pattern against fourteen
unrelated tenants of the same address, including several with more than
seventy names apiece, found none carrying it. That measurement is what moved
them from a hunch to an indicator.
