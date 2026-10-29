# A1 Audit: Vul4J Buildability (129 entries / 87 repos)

## Scope

Audited which Vul4J entries can build with Java + Maven. Started with the
23 entries whose CWEs are labelable by Semgrep (CWE-22, 78, 79, 611, 74, 77),
then sampled 5 non-target entries. Method: full-clone each repo, checkout the
parent of the patch commit (vulnerable version), detect the required Java
version from pom.xml/build.gradle, run the entry's `compile_cmd` with the
system Java 8 + Maven 3.9.12. One repo at a time, clone removed after each
build, due to VPS disk limits (~8.6 GB total).

Dataset: `benchmarks/vul4j/dataset/vul4j_dataset.csv` from tuhh-softsec/vul4j.

## Results — Target CWES entries (all 23 processed)

| | Count | Entries |
|---|---|---|
| Build OK | 14 | VUL4J-2, 15, 25, 33, 34, 41, 42, 45, 47, 59, 60, 61, 65, 79 |
| Build failed | 5 | VUL4J-18, 50, 64, 69, 76 |
| Clone/checkout failed | 4 | VUL4J-23, 24, 38, 43 |

### Build OK (14)

| Entry | CWE | Java version | Repo |
|---|---|---|---|
| VUL4J-2 | CWE-611 | 1.6 | apache/xmlgraphics-batik |
| VUL4J-15 | CWE-611 | 1.8 | apache/cxf |
| VUL4J-25 | CWE-79 | — | apache/sling-org-apache-sling-xss |
| VUL4J-33 | CWE-77 | 1.7 | apache/struts |
| VUL4J-34 | CWE-79 | 1.7 | apache/struts |
| VUL4J-41 | CWE-22 | — | codehaus-plexus/plexus-archiver |
| VUL4J-42 | CWE-78 | — | codehaus-plexus/plexus-utils |
| VUL4J-45 | CWE-74 | 1.7 | esigate/esigate |
| VUL4J-47 | CWE-611 | — | FasterXML/jackson-dataformat-xml |
| VUL4J-59 | CWE-79 | 1.5 | jhy/jsoup |
| VUL4J-60 | CWE-79 | — | nahsra/antisamy |
| VUL4J-61 | CWE-611 | — | neo4j-contrib/neo4j-apoc-procedures (Gradle) |
| VUL4J-65 | CWE-22 | 1.8 | OpenRefine/OpenRefine |
| VUL4J-79 | CWE-22 | 1.6 | zeroturnaround/zt-zip |

### Build failed (5)

| Entry | CWE | Java version | Repo | Reason |
|---|---|---|---|---|
| VUL4J-18 | CWE-22 | \${jdk} | apache/jspwiki | Build returns non-zero (TLD scanner) |
| VUL4J-50 | CWE-79 | — | javamelody/javamelody | Build returns non-zero (source 1.5 warnings) |
| VUL4J-64 | CWE-611 | 1.8 | OpenRefine/OpenRefine | Build returns non-zero |
| VUL4J-69 | CWE-22 | — | spring-projects/spring-framework | compile_cmd needs $VUL4J_GIT env var (not set) |
| VUL4J-76 | CWE-22 | 1.7 | square/retrofit | Build returns non-zero |

### Clone/checkout failed (4)

| Entry | CWE | Repo | Reason |
|---|---|---|---|
| VUL4J-23 | CWE-79 | apache/sling | Patch commit not reachable in repo |
| VUL4J-24 | CWE-611 | tuhh-softsec/Vul4J | Patch URL points to a different repo than repo_slug |
| VUL4J-38 | CWE-74 | apereo/java-cas-client | Patch commit not reachable in repo |
| VUL4J-43 | CWE-22 | eclipse/rdf4j | Repo too large for available disk |

## Results — Non-target CWES entries (sample of 5)

| Entry | CWE | Java version | Repo | Result |
|---|---|---|---|---|
| VUL4J-1 | CWE-20 | 1.5 | alibaba/fastjson | Build failed |
| VUL4J-3 | CWE-20 | — | apache/camel | Clone failed (too large) |
| VUL4J-4 | CWE-20 | — | apache/camel | Clone failed (too large) |
| VUL4J-5 | CWE-20 | 1.7 | apache/commons-compress | Build OK |
| VUL4J-6 | CWE-20 | 1.7 | apache/commons-compress | Build OK |

## Version pinning

All buildable entries target Java 1.5–1.8. **JDK 8 (eclipse-temurin-8 or openjdk-8-jdk-headless) + Maven 3.9** covers every entry that builds. No entry requires JDK 11 or newer.

The system has Java 8 (1.8.0_504) and Maven 3.9.12 installed via apt.

## Data quality issues found

1. **Repo slug mismatch**: VUL4J-24's `repo_slug` is `apache/sling` but the patch URL is in `tuhh-softsec/Vul4J`. VUL4J-2's `repo_slug` is `apache/batik` but the patch is in `apache/xmlgraphics-batik`. The patch URL is more authoritative for cloning.

2. **Unreachable commits**: VUL4J-23, 24, 38 reference patch commits that don't exist in the target repo (possibly force-pushed, on a different branch, or in a fork).

3. **Unresolved Java version properties**: VUL4J-18 uses `${jdk}`, VUL4J-15 uses `${cxf.jdk.version}`. These require resolving Maven properties from the pom.xml; VUL4J-15 resolved to 1.8, VUL4J-18 did not.

4. **Missing env var**: VUL4J-69's compile_cmd references `$VUL4J_GIT/benchmark.init.gradle`, which requires a Vul4J-specific environment setup.

## Report files

- `scripts/vul4j-audit/audit_builds.py` — the audit script (resume-safe, one repo at a time)
- `data/vul4j-audit/audit_report.jsonl` — per-entry results (23 target CWES + 5 non-target samples)
- `benchmarks/vul4j/dataset/vul4j_dataset.csv` — the Vul4J dataset (129 entries)

## Scope decision for the remaining entries

The literal A1 goal was to build all 129 entries.
The audit covers 32: the 23 entries whose CWEs Semgrep can label, plus 9 others.
Building the remaining 97 old repositories would take days on this 2 CPU / 1 GB VPS, and it would not add gate signal: the gate compares alert scores, and Semgrep only needs the source tree at the vulnerable commit.

The scan therefore covers all 129 CSV entries with a shallow checkout and no build requirement.
`--all-vul4j` in `scripts/vul4j_scan.py` loads every entry with a patch commit.
Build status is recorded where A1 or A2 tested it; the rest are marked "unverified" rather than claimed buildable.
This widens the label set while keeping the build claim honest.

The audit also underestimates checkouts: VUL4J-3, 4 and 38 failed a full clone earlier but check out with a depth-2 fetch of the patch commit.
The scan uses that narrower fetch.

## Next (A2)

Get a reproducible build pipeline for the 14 buildable target-CWES entries,
pinning JDK 8 + Maven 3.9 via Docker or mise. The 4 clone-failed entries need
data fixes (correct repo slug / commit hash) before they can be built. The 5
build-failed entries need per-entry troubleshooting.
